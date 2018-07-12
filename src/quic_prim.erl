%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%% 
%%% The quic_prim module is a gen_statem for providing flow control,
%%% congestion control, and reliability over a udp socket.
%%% The gen_statem is registered via the quic_registry module and
%%% creates a single interface over the socket for all quic streams.
%%% This state machine effectively acts as the stream 0 of the quic
%%% connection.
%%% Prior to sending information packet headers (including packet 
%%% numbers) are assigned via this process. All packets are received,
%%% parsed, and acked via this process as well. This is a potential
%%% bottleneck to explore in the future.
%%%
%%% Unsent and Unacked packets are stored in a priority queue and 
%%% moved to a second priority queue after being sent, but still unacked.
%%% When the packet is acked, it is removed from the second priority queue.
%%% The priority queues are ranked by packet number. The purpose of
%%% the second queue is to reduce the impact of filtering out acks,
%%% which is O(n).
%%%
%%% @end
%%% Created : 29 Jun 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_prim).

-behaviour(gen_statem).

-export([connect/4]).
-export([send/2]).
-export([recv/3]).
-export([controlling_process/2]).
-export([close/1]).

%-include("quic_headers.hrl").


-record(quic_conn,
        {type         :: client | server,
         socket       :: inet:socket(),
         address      :: inet:socket_address() |
                         inet6:socket_address(),
         port         :: inet:port_number(),
         owner        :: pid(),
         dest_conn_ID :: non_neg_integer(),
         src_conn_ID  :: non_neg_integer()
        }).

-record(quic_data, 
        {version          :: #quic_version{},
         window_timeout   :: {reference(), 
                              non_neg_integer()},
         conn             :: #quic_conn{},
         buffer = []      :: [term()], 
         %% buffers out of order packets in handshake.
         init_pkt_num = 0 :: non_neg_integer(),
         hand_pkt_num = 0 :: non_neg_integer(),
         app_pkt_num  = 0 :: non_neg_integer(),
         sent             :: orddict:orddict(),
         ready            :: quic_staging:staging(),
         priority_num     :: non_neg_integer(),
         recv             :: {list(), list()} | 
                             {active, Owner :: pid(), 
                              N :: non_neg_integer()} |
                             {active, Owner :: pid()},
         params           :: #quic_params{},
         current_data     :: non_neg_integer(),
         next_stream_id   :: non_neg_integer()
        }).


%% These records will be used for default options given by connect
%% or listen. Only the Server can set preferred_address and reset_token
%% The params are communicated in the handshake messages by both parties.
%%
%% Currently they are not used and might be used until quic is finalized.

-opaque(version, non_neg_integer()).

%% Currently only one version.
-record(quic_version, 
        {initial_version    :: version(),
         negotiated_version :: version(),
         supported_versions :: [version()]
        }).

-record(quic_params, 
        {init_max_stream_data  :: non_neg_integer(),
         init_max_data         :: non_neg_integer(),
         idle_timeout = 600000 :: non_neg_integer(),
         init_max_bi_streams   :: non_neg_integer(),
         init_max_uni_streams  :: non_neg_integer(),
         max_packet_size       :: non_neg_integer(),
         ack_delay_exp = 3     :: non_neg_integer(),
         migration = true      :: boolean(),
         reset_token = <<>>    :: binary(),
         preferred_address     :: #quic_pref_addr{}
        }).

-record(quic_pref_addr, 
        {address     :: inet:socket_address() |
                        inet6:socket_address(),
         port        :: inet:port_number(),
         conn_id     :: non_neg_integer(),
         reset_token :: binary()
        }).
                         

%% gen_statem callbacks
-export([callback_mode/0, init/1, terminate/3, code_change/4]).
-export([state_name/3]).


%%%===================================================================
%%% API
%%%===================================================================

-spec connect(Address, Port, Opts, Timeout) -> Result when
    Address :: inet:socket_address(),
    Port :: inet:port_number(),
    Opts :: [Opt],
    Opt :: gen_quic:option(),
    Timeout :: non_neg_integer(),
    Result :: {ok, Socket} | {error, Reason},
    Socket :: inet:socket(),
    Reason :: gen_quic:errors().

connect(Address, Port, Opts, Timeout) ->
  {ok, Quic_Opts} = inet_quic_util:parse_opts(Opts),
  %% Open the socket in passive mode. inet_udp uniquifies the 
  %% options (chooses first) and ignores invalid options.
  {ok, Socket} = inet_udp:open([{active, false} | Opts]),

  Conn = #quic_conn{type = client,
                    socket = Socket,
                    address = Address,
                    port = Port,
                    owner = self()
                   },

  %% Name the gen_server after the socket.
  {ok, Pid} = gen_statem:start_link(via(Socket), ?MODULE, 
                                    [client, Conn, Quic_Opts], []),

  inet_udp:controlling_process(Socket, Pid),
  %% Transfer ownership of the socket to the gen_server.
  %% Try performing the handshake operation. Return the result,
  %% either {error, timeout} | {ok, Socket} | {error, Reason}
  %% Reason could be version negotiation or other packet type.
  gen_statem:call(Pid, {connect, Timeout}).


-spec accept(Conn, Options, Timeout) -> Result when
    Conn :: #quic_conn{},
    Options :: [gen_quic:option()],
    Timeout :: non_neg_integer() | infinity,
    Result :: {ok, Socket} | {error, Reason},
    Reason :: gen_quic:errors().

accept(Conn0, Options, Timeout) ->
  %% Open a new socket for the connection.
  {ok, Socket} = inet_udp:open(Options),

  Conn = Conn0#quic_conn{socket=Socket},
  %% Start a new gen_statem for the socket and connection.
  {ok, Pid} = gen_statem:start_link(via(Socket), 
                                    ?MODULE, 
                                    [server, Conn, Options], 
                                    []),
  %% Transfer ownership of the socket.
  inet_udp:controlling_process(Socket, Pid),
  
  %% Have it send an accept message back to the client.
  %% This will start the handshake procedure and not return until completed / error.
  gen_statem:call(Pid, {accept, Timeout}).


-spec send(Socket, Data) -> Result when
    Socket :: gen_quic:socket(),
    Data :: binary() | {Staging_Type, binary()},
    Staging_Type :: packed | unpacked,
    Result :: ok | {error, Reason},
    Reason :: gen_quic:errors().

send(Socket, Data) when is_tuple(Data) ->
  gen_statem:call(via(Socket), {send, Data});

send(Socket, Data) ->
  %% Have the default be unpacked for now.
  %% Probably should handle this case in the statem since
  %% it knows the connection options.
  gen_statem:call(via(Socket), {send, {unpacked, Data}}).


-spec recv(Socket, Timeout) -> Result when
    Socket :: gen_quic:socket(),
    Timeout :: non_neg_integer(),
    Result :: {ok, Data} | {error, Reason},
    Data :: binary() | #quic_stream{},
    Reason :: gen_quic:errors().
%% Data may be a quic_stream record if a stream is opened 
%% by the other side of the connection.

recv(Socket, Timeout) ->
  gen_statem:call(via(Socket), {recv, Timeout}).


-spec controlling_process(Socket, Pid) -> Result when
    Socket :: gen_quic:socket(),
    Pid :: pid(),
    Result :: ok | {error, Reason},
    Reason :: gen_quic:errors().

controlling_process(Socket, Pid) ->
  gen_statem:call(via(Socket), {new_owner, Pid}).


-spec close(Socket) -> ok when
    Socket :: gen_quic:socket().

close(Socket) ->
  gen_statem:close(via(Socket), normal, infinity).

%%%===================================================================
%%% gen_statem callbacks
%%%===================================================================

-spec callback_mode() -> gen_statem:callback_mode_result().

callback_mode() -> state_functions.


-spec init(Args :: term()) ->
              gen_statem:init_result(atom()).

init([client, Conn, Options]) ->
  process_flag(trap_exit, true),
  {ok, Params} = quic_packet:set_defaults(client, Options),
  %% Creates an initial set of connection defaults from the version
  %% and options.
  
  Recv = get_recv_state(Conn#quic_conn.owner, Options),

  %% TODO: Change quic_staging to option variable.
  State = #quic_data{conn=Conn, 
                     ready = quic_staging:new(low),
                     sent = orddict:new(),
                     priority_num = 1,
                     recv = Recv,
                     params = Params
                    },

  {ok, init_client, State};

init([server, Conn, Options]) ->
  process_flag(trap_exit, true),
  
  Recv = get_recv_state(Conn#quic_conn.owner, Options),
  
  {ok, Params} = quic_packet:set_defaults(server, Options),

  %% TODO: Change quic_staging to option variable
  State = #quic_data{conn = Conn,
                     ready = quic_staging:new(low),
                     send = orddict:new(),
                     priority_num = 1,
                     recv = Recv,
                     params = Params
                    },
  
  {ok, init_server, State}.


-spec do_send(Conn, Packet) -> ok | {error, Reason} when
    Conn :: #quic_conn{},
    Packet :: binary(),
    Reason :: gen_quic:errors().
%% Wrapper function.
do_send(#quic_conn{socket = Socket,
                   address = Address,
                   port = Port
                  },
        Packet) ->
  prim_inet:sendto(Socket, Address, Port, Packet).


init_client({call, From}, {connect, Timeout}, 
            #quic_data{conn = Conn0,
                       init_pkt_num = IPN,
                       params = Params
                      } = Data) ->
  
  ok = inet:setopts(Conn0#quic_conn.socket, [{active, once}]),
  %% Socket ownership is transferred so now put it in active state.
  %% Using active once for the connect handshake.
  %% do_connect creates and sends the version specific handshake packet.
  {ok, Conn, Packet} = 
    quic_crypto:form_packet(initial, Conn0, IPN,
                            Params#quic_params.reset_token),
  
  ok = do_send(Conn, Packet),
  %% If connection is successful, the state will receive a packet over
  %% the socket. Keep initial packet in timer for resending.
  Timer = erlang:start_timer(100, self(),
                             {initial, Packet, 1}),

  %% Create a timer for the entire handshake process in actions.
  {keep_state, Data#quic_data{window_timeout = {Timer, 100},
                              conn = Conn
                             },
   [{{timeout, connect}, Timeout, {error, timeout}}]};


init_client(info, {timeout, _Ref, 
                   {initial, Packet, Attempt}},
            #quic_data{conn = Conn, 
                       window_timeout = {_Ref, Timeout}}
            = Data) when Attempt < 5->
  %% Timed out without response. Send again.
  ok = do_send(Conn, Packet),

  %% Set timeout at twice the previous timeout.
  Timer = erlang:start_timer(Timeout * 2, self(), 
                             {initial, Packet, Attempt + 1}),
  
  {keep_state, 
   Data#quic_data{window_timeout = {Timer, Timeout*2}}};


init_client(info, {udp, Socket, Address, Port, Packet0},
            #quic_data{conn = 
                         #quic_conn{socket = Socket,
                                    owner = Owner,
                                   } = Conn0,
                       recv = Recv,
                       window_timeout = {Timer, Timeout},
                       init_pkt_num = IPN,
                       buffer = Buffer,
                       params = Params
                      } = Data0) ->
  %% Packet was received. Parse it and see what it is.

  Conn = Conn0#quic_conn{address = Address, port = Port},
  Data = Data0#quic_data{conn = Conn},
  
  case quic_crypto:parse_packet(Packet0, Data) of
    not_quic ->
      keep_state_and_data;

    invalid_quic ->
      %% Most likely the connection info from the server does not
      %% match the supplied client side info.
      %% Destination Connection IDs or Source Connection IDs.
      %% This case might be processed as not_quic since decoding the
      %% packet requires the correct IDs.
      keep_state_and_data;
    
    {coalesced, Packets} ->
      %% This happens when the single datagram contains
      %% several quic packets. In order to handle each of
      %% them in succession, handle_coalesced is called.
      %% TODO: Check spelling on coalesced.

      erlang:cancel_timer(Timer),

      %% Processes all initial packets in order by calling 
      %% handle_init and buffers remaining packets.
      handle_coalesced(Data, Packets);


    {initial, Data1, Packet, Crypto} ->
      ?DBG("Initial response received.~n", []),
      %% correct in order response. No need to buffer.
      
      %% Cancel timer since response was received.
      erlang:cancel_timer(Timer),
      
      %% Validates handshake and either keeps state to wait for more
      %% initial packets, or moves to handshake state.
      handle_init(Data1, Packet, Crypto);
    
    {vx_neg, Versions} = Version_Neg ->
      ?DBG("Version Negotiation Packet Received.~n", []),
      
      %% Version negotiation is to be handled by the application.
      %% Send a reply to the caller.
      gen_statem:reply(Owner, {error, Version_Neg}},

      %% Cancel the timer and shutdown.
      erlang:cancel_timer(Timer),
      {stop, shutdown};
    
    {retry, New_Data0} ->
      ?DBG("Retry packet received.~n", []),

      %% The updated Conn should have the info to send a
      %% new correct initial packet.
      %% Parsed Data might have a crypto token included.
      erlang:cancel_timer(Timer),
      
      %% Forms a new initial packet from the parsed retry packet.
      {ok, New_Data1, Packet} = 
        quic_crypto:form_packet(initial, New_Data0),
      
      ok = do_send(New_Data1#quic_conn.conn, Packet),
      
      %% This resets the timeout attempt counter, but it keeps the
      %% same timeout length as the previous attempt.
      %% Might not be appropriate, but if a retry packet
      %% is received the next initial packet will probably
      %% succeed.
      Timer1 = erlang:start_timer(self(), Timeout,
                                  {initial, Packet, 1}),
      {keep_state, New_Data1};

    protected ->
      ?DBG("Protected packet received~n", []),
      %% Out of order packet received.
      %% Don't know how to decode it yet.
      %% Queue the packet on the buffer.

      %% Cancel timer since now the server will deal with
      %% ensuring reliability.
      erlang:cancel_timer(Timer),
      
      {keep_state, 
       Data#quic_data{
         buffer = [{protected, Packet0} | Buffer]}};
    
    handshake ->
      ?DBG("Handshake Packet received~n", []),
      %% Out of order packet.
      %% Don't know how to decode it yet.
      %% Queue the packet on the buffer.
      
      %% Cancel timer since now the server will deal with
      %% ensuring reliability.
      erlang:cancel_timer(Timer),
      
      {keep_state,
       Data#quic_data{
         buffer = [{handshake, Packet0} | Buffer]}};

    {quic_error, Reason} ->
      %% Could be a parsing error or an error transmission
      %% from the server.
      ?DBG("Quic error: ~p~n", [Reason]),

      %% A reply still needs to be sent to the owner.
      gen_statem:reply(Owner, {error, Reason}),

      %% Shutdown in this case too.
      erlang:cancel_timer(Timer),
      {stop, shutdown}

  end;

init_client({timeout, connect}, Message, #quic_data{conn = Conn}) ->
  %% Timeout for entire connection handshake process.
  %% Also needs to be processed in the handshake_client state.
  {stop_and_reply, {Conn#quic_conn.owner, Message}}.


init_server({call, From}, {accept, Timeout} 
            #quic_data{conn = Conn,
                      } = Data0) ->
  %% Switch socket to active once since ownership is confirmed at
  %% this point.
  %% Note: Using {active, 1} here instead of {active, once}.
  %% This allows for {active, 1} to also be called in the handshake
  %% state and thus to expect 2 active receipts.
  ok = inet:setopts(Conn0#quic_conn.socket, [{active, 1}]),
  
  %% retry and version negotiation packets are handled in quic_server
  %% Only a successful initial packet is being handled by this
  %% statem.
  %% Need to send an initial packet and handshake packet.
  %% Optional to send protected data. Will handle that later.
  %% Conn will not change. Data will change (packet numbers).
  {Data1, Sent_Packet} = 
    case quic_crypto:form_packet(initial_response, Data) of
      {ok, Data, Packets} when is_list(Packets) ->
        %% The packets could not be completely coalesced so we have to
        %% fold over the list of packets and send each one.
        %% ok as Acc ensures all are sent correctly
        ok = lists:foldl(fun(Packet, ok) -> do_send(Conn, Packet) end,
                         ok, Packets),
        {Data, Packets};
    
      {ok, Data, Packet} ->
        %% The packets were coalesced so there is only one packet
        %% to send.
        ok = do_send(Conn, Packet),
        {Data, Packet}

        %% Crash on any other case.
    end,
  
  %% Start 100 ms timer.
  Timer = erlang:start_timer(100, {init_server, Sent_Packet, 1}),

  %% Start handshake timer in state actions. Needs to be cancelled
  %% when handshake_server succeeds.
  {next_state, handshake_server,
   Data1#quic_data{window_timeout = {Timer, 100}},
   [{{timeout, accept}, Timeout, {error, timeout}}]}.


%% The handshake_client state is responsible for performing the
%% crypto handshake for the client. A validated handshake from the
%% server sends a handshake packet with the TLS FIN record.
%% Needs to end with a reply to the process owner.
%% First check if there are any handshake messages in the buffer to
%% process.


handshake_client(internal, check_buffer,
                 #quic_data{buffer = []} = Data) ->
  %% Nothing in the buffer to check
  keep_state_and_data;


handshake_client(internal, check_buffer,
                 #quic_data{buffer = Buffer} = Data) ->
  %% Something to check. Get all handshake packets from buffer and
  %% see if they finish the handshake process.
  %% handle_handshake will either transition to next state (protected)
  %% or keep state and wait for more handshake packets to arrive.
  case lists:keyfind(handshake, 1, Buffer) of
    
    [] ->
      %% No handshake packets processed yet so wait for them.
      keep_state_and_data;
    
    Packets ->
      %% Woohoo something to do already.
      handle_handshake(Packets, Data)
  end;

handshake_client(info, {udp, Socket, Address, Port, Packet0},
                #quic_data{conn = 
                             #quic_conn{socket = Socket,
                                        address = Address,
                                        port = Port
                                       } = Conn0,
                           window_timeout = {Timer, Timeout},
                           buffer = Buffer,
                          } = Data0) ->
  %% Packet from the correct socket, address, and port
  %% See if it's what we need.
  case quic_crypto:parse_packet(Packet0, Data0) of
    {handshake, Data, Packet, Crypto} ->
      %% Woohoo got a handshake packet.
      
      handle_handshake(Data, Packet, Crypto);

    protected ->
      %% out of order, queue it and repeat.
      {keep_state, 
       Data0#quic_data{buffer = Buffer ++ [{protected, Packet0}]}};
    
    {coalesced, Packets} ->
      %% multiple packets were coalesced, call handle_coalesced to
      %% handle each packet appropriately.
      %% Either keeps state and waits for more packets or handles the
      %% handshake packets and transitions to the protected state.
      handle_coalesced(Data0, Packets);
    
    {initial, Data, Packet, Crypto} ->
      %% This could happen for out of order packets and late packet
      %% arrivals. If the packet number for this packet is less than
      %% that of the last processed initial packet, drop this one.
      %% Checked in handle_initial.
      handle_initial(Data, Packet, Crypto);
    
    {quic_error, Reason} ->
      %% Could be a parsing error or an error transmission
      %% from the server.
      ?DBG("Quic error: ~p~n", [Reason]),

      %% A reply still needs to be sent to the owner.
      gen_statem:reply(Owner, {error, Reason}),

      %% Shutdown in this case too.
      erlang:cancel_timer(Timer),
      {stop, shutdown};

    not_quic ->
      keep_state_and_data;
    
    _Other ->
      %% We're in the middle of a handshake where we already agreed
      %% on version number and connection info, so ignore everything
      %% else. They're probably late packets.
      keep_state_and_data
  end;

handshake_client({timeout, connect}, Message, #quic_data{conn = Conn}) ->
  %% Timeout for entire connection handshake process.
  {stop_and_reply, {Conn#quic_conn.owner, Message}}.


%% When the server is in the handshake_server state, it has a timer
%% for the sent initial and handshake packets. The server is waiting
%% for a handshake packet from thd client indicating that the TLS
%% connection has finished (the FIN message). When/if it arrives,
%% the server cancels the accept timer and transitions into the
%% protected state where unlimited sending and receiving take place.
%% Acks are sent back for the handshake fin message.
%% The socket is also set to {active, true} so that the state
%% machine can process packets separately from the application space
%% Upon transition into this state, the server has sent all info
%% that the client requires to use 1-RTT packets. Any 0-RTT packets
%% that arrived throughout the handshake procedure get acked upon
%% entry to this state in the 1-RTT packet number space.
handshake_server()


handle_event(info, {udp_passive, Socket}, 
             #quic_data{conn =
                          #quic_conn{socket = Socket}}) ->
  %% maintains the connection in an {active, once} state while
  %% the connection handshake is being performed.
  %% After the handshake is successful, the socket is
  %% maintained in an active, true state and this shouldn't
  %% be called.
  ok = inet:setopts(Socket, [{active, once}]),
  keep_state_and_data;

handle_event(info, {timeout, _Ref, {State, _, _}}, 
             #quic_data{conn = Conn,
                        window_timeout = {_Ref, _Time}}) ->
  %% Complete timeout.
  %% Reply needs to be sent to the owning process.
  gen_statem:reply(Conn#quic_conn.owner, {error, timeout}),
  {stop, shutdown};

handle_event(info, _, _) ->
  %% Ignore all other event info messages that occur.
  keep_state_and_data.



-spec terminate(Reason :: term(), State :: term(), Data :: term()) ->
                   any().

terminate(_Reason, _State, _Data) ->
  void.


-spec code_change(
        OldVsn :: term() | {down,term()},
        State :: term(), Data :: term(), Extra :: term()) ->
                     {ok, NewState :: term(), NewData :: term()} |
                     (Reason :: term()).

code_change(_OldVsn, State, Data, _Extra) ->
  {ok, State, Data}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

via(Socket) ->
  {via, quic_registry, Socket}.


get_recv_state(Owner, Options) ->
  case inet_quic_util:get_opt(Options, active) of
    none ->
      %% The default will be active.
      {active, Owner};
    
    {acive, true} ->
      {active, Owner};
    
    {active, false} ->
      %% Packets are stored in a makeshift queue.
      %% { InOrder list, Reversed List }
      {[], []};
    
    {active, once} ->
      %% Change once to an integer.
      {active, Owner, 1};
    
    {active, N} ->
      {active, Owner, N}
  end.


%% handle_recv either queues parsed data and returns 
%% {List, List} or sends the packet to the owner and 
%% returns an updated recv state.

-spec handle_recv(Recv_State, Data, Socket) -> Recv_State when
    Recv_State :: {[Data], [Data]} |
                  {active, Owner} |
                  {active, Owner, non_neg_integer()},
    Data :: binary() | #quic_stream{},
    Socket :: gen_quic:socket(),
    Owner :: pid().

handle_recv(Recv, <<>>, _Socket) ->
  %% This clause is to make logic of handling 0-RTT data more smooth.
  %% Obviously if there is no data to handle, there's nothing to do.
  Recv;

handle_recv({[], []}, Data, _Socket) ->
  {[Data], []};

handle_recv({[], Items}, Data, _Socket) ->
  {lists:reverse([Data | Items]), []};

handle_recv({Next, Rest}, Data, _Socket) ->
  {Next, [Data | Rest};

handle_recv({active, Owner}, Data, Socket) ->
  Owner ! {quic, Socket, Data},
  {active, Owner};

handle_recv({active, Owner, N}, Data, Socket) when N > 1 ->
  Owner ! {quic, Socket, Data},
  {active, Owner, N-1};

handle_recv({active, Owner, 1}, Data, Socket) ->
  Owner ! {quic, Socket, Data},
  Owner ! {quic_passive, Socket},
  {[], []}.


handle_init(#quic_data{conn = #quic_conn{socket = Socket,
                                         owner = Owner,
                                        } = Conn0,
                       recv = Recv,
                       window_timeout = {Timer, Timeout},
                       init_pkt_num = IPN,
                       buffer = Buffer,
                       params = Params
                      } = Data0, 
            Packet, Crypto) ->
      
  %% Initial server packet should contain ack for initial packet
  %% Would contain crypto server handshake frames too.
  %% TODO: Add logic to check if server handshake is valid.

  case quic_crypto:valid_handshake(Data0, Crypto) of
    
    {valid, Data} ->
      %% Server handshake message(s) were completely 
      %% validated. Move to next state for more
      %% handshake messages and check if any buffered
      %% handshake messages were received.

      %% TODO: Ack initial packet(s).

      {next_state, handshake_client, 
       Data#quic_data{recv = handle_recv(Recv, Packet, Socket)},
       [{next_event, internal, check_buffer}]};
        
    {incomplete, Data} ->
      %% There are more initial messages to receive
      %% with crypto data. Remain in this state and
      %% wait for them.
      %% Don't send acks yet.
      
      {keep_state, Data};
        
    {invalid, Reason} ->
      %% The initial crypto messages are invalid.
      %% TODO: verify what to do in this case.
      %% Exit with error
          
      {stop_and_reply, shutdown, {Conn#quic_conn.owner, 
                                  {error, Reason}}}
  end.


%%handle_coalesced()
%% This will be several packets together.
%% Process each of them in order
%% Ideal situation is initial -> handshake -> protected.
%% Possible is initial (repeated) or (process initial repeatedly)
%% initial -> handshake or (process initial and handshake)
%% handshake -> protected (add to buffer and keep_state)
