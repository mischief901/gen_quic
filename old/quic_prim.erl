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

%% TODO: Change packet resends so that the packet number is incremented.

%% TODO: Consider separating server and client into two different state machines.
%% Or just change quic_server to be the server state machine and quic_prim
%% to be quic_client state machine.

%% TODO: Consider changing the info udp packet receives to a common state.
%% Potentially this would cut down on overall code size. After parsing
%% the packet send it or cast it to itself. Might need to adjust the
%% parsing to be {unknown, Packet} if it cannot be parsed yet (due to
%% lack of crypto keys) instead of just returning handshake or protected.
%% First just finish the module though.

-module(quic_prim).

-behaviour(gen_statem).

-export([connect/4]).
-export([send/2]).
-export([recv/2]).
-export([controlling_process/2]).
-export([close/1]).
-export([accept/3]).

-include("quic_headers.hrl").

                         

%% gen_statem callbacks
-export([callback_mode/0, init/1, terminate/3, code_change/4]).

-export([init_client/3, init_server/3, handshake_client/3, handshake_server/3]).
-export([protected/3, await_finished/3]).

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
  
  Data = #quic_data{
            type = client,
            conn = #quic_conn{
                      socket = Socket,
                      address = Address,
                      port = Port,
                      owner = self()
                     }
           },

  %% Name the gen_server after the socket.
  {ok, Pid} = gen_statem:start_link(via(Socket), ?MODULE, 
                                    [Data, Quic_Opts], []),

  inet_udp:controlling_process(Socket, Pid),
  %% Transfer ownership of the socket to the gen_server.
  %% Try performing the handshake operation. Return the result,
  %% either {error, timeout} | {ok, Socket} | {error, Reason}
  %% Reason could be version negotiation or other packet type.
  gen_statem:call(Pid, {connect, Timeout}).


-spec accept(Data, Frames, TLS_Info) -> Result when
    Data :: #quic_data{},
    Frames :: [quic_frame()],
    TLS_Info :: #tls_record{},
    Result :: {ok, Socket} | {error, Reason},
    Socket :: gen_quic:socket(),
    Reason :: gen_quic:errors().

accept(#quic_data{conn = Conn0} = Data0, Frames, TLS_Info) ->
  %% Open a new socket for the connection.
  {ok, Socket} = inet_udp:open([{active, false}]),

  Data = Data0#quic_data{
           conn = Conn0#quic_conn{socket=Socket}
          },
  %% Start a new gen_statem for the socket and connection.
  {ok, Pid} = gen_statem:start_link(via(Socket), 
                                    ?MODULE, 
                                    [Data, Frames, TLS_Info], 
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


-spec init(Args) -> Result when
    Args :: [Type | Conn | Options],
    Type :: client | server,
    Conn :: #quic_conn{},
    Options :: [Option],
    Option :: gen_quic:option(),
    Result :: {ok, State, #quic_data{}},
    State :: init_client | init_server.

init([#quic_data{
         type = client,
         conn = Conn
        } = Data0, 
      Options]) ->
  process_flag(trap_exit, true),
  {ok, Params} = quic_crypto:default_params(client, Options),
  %% Creates an initial set of connection defaults from the version
  %% and options.
  
  Recv = get_recv_state(Conn#quic_conn.owner, Options),

  %% TODO: Change quic_staging to option based variable.
  Data = Data0#quic_data{
           ready = quic_staging:new(low),
           sent = orddict:new(),
           priority_num = 1,
           recv = Recv,
           params = Params
          },

  {ok, init_client, Data};

init([#quic_data{
         type = server,
         conn = Conn
        } = Data0, 
      Options, Timeout]) ->
  
  process_flag(trap_exit, true),
  
  Recv = get_recv_state(Conn#quic_conn.owner, Options),
  
  {ok, Params} = quic_crypto:default_params(server, Options),

  %% TODO: Change quic_staging to option based variable
  Data = Data0#quic_data{
           ready = quic_staging:new(low),
           sent = orddict:new(),
           priority_num = 1,
           recv = Recv,
           params = Params
          },
  
  {ok, init_server, Data}.


-spec init_client(Event, Message, Data) -> Result when
    Event :: {call, From} |
             info |
             {timeout, connect},
    From  :: pid(),
    Message :: {connect, Timeout} |
               {timeout, Timer_Ref, Timeout_Message} |
               UDP_Message,
    Timeout :: non_neg_integer() | infinity,
    Timer_Ref :: reference(),
    Timeout_Message :: {initial_client, Attempt},
    Attempt :: non_neg_integer(),
    UDP_Message :: {udp, Socket, Address, Port, Packet},
    Socket :: inet:socket(),
    Address :: inet:socket_address(),
    Port :: inet:port_number(),
    Packet :: binary(),
    Data :: #quic_data{},
    Result :: {keep_state, Data} |
              keep_state_and_data |
              {next_state, handshake_client, #quic_data{}, Actions} |
              {next_state, handshake_client, #quic_data{}} |
              {stop_and_reply, shutdown, {From, {error, Reason}}} |
              {stop, shutdown},
    Actions :: term(),
    Reason :: gen_quic:errors() | timeout.

init_client({call, From}, {connect, Timeout}, 
            #quic_data{conn = Conn} = Data0) ->
  
  ok = inet:setopts(Conn#quic_conn.socket, [{active, once}]),
  %% Socket ownership is transferred so now put it in active state.
  %% Using active once for the connect handshake.
  
  Data = quic_crypto:crypto_init(Data0),
  
  %% Sends and forms the initial client hello message called on 
  %% resend operations also.
  Data1 = send_and_form_packet(initial_client, Data),

  %% If connection is successful, the state will receive a packet over
  %% the socket. Keep initial packet in timer for resending.
  Timer = erlang:start_timer(100, self(), {initial_client, 1}),
  
  %% Create a timer for the entire handshake process in actions.
  {keep_state, Data1#quic_data{
                 window_timeout = {Timer, 100}
                },
   [{{timeout, connect}, Timeout, {error, timeout}}]};


init_client(info, {timeout, _Ref, {initial_client, Attempt}},
            #quic_data{conn = Conn, 
                       window_timeout = {_Ref, Timeout}
                      } = Data0) when Attempt < 5->

  %% Timed out without response. Form a new packet and send again.
  Data = send_and_form_packet(initial_client, Data0),

  %% Set timeout at twice the previous timeout.
  Timer = erlang:start_timer(Timeout * 2, self(), 
                             {initial_client, Attempt + 1}),
  
  {keep_state, 
   Data#quic_data{window_timeout = {Timer, Timeout * 2}}};


init_client(info, {udp, Socket, Address, Port, Packet0},
            #quic_data{conn = 
                         #quic_conn{socket = Socket,
                                    owner = Owner
                                   } = Conn0,
                       recv = Recv,
                       window_timeout = {Timer, Timeout},
                       init_pkt_num = IPN,
                       buffer = Buffer,
                       params = Params
                      } = Data0) ->
  %% Packet was received. Parse it and see what it is.
  %% Could be from different port/address.
  Conn = Conn0#quic_conn{address = Address, port = Port},
  Data = Data0#quic_data{conn = Conn},
  
  case quic_crypto:parse_packet(Packet0, Data) of
    not_quic ->
      %% Drop it and wait for another.
      keep_state_and_data;

    invalid_quic ->
      %% Most likely the connection info from the server does not
      %% match the supplied client side info.
      %% Destination Connection IDs or Source Connection IDs.
      %% This case might be processed as not_quic since decoding the
      %% packet requires the correct IDs.
      %% Drop it and wait.
      keep_state_and_data;
    
    %% {coalesced, Packets} ->
    %% Not implemented yet.
    %%   %% This happens when the single datagram contains
    %%   %% several quic packets. In order to handle each of
    %%   %% them in succession, handle_coalesced is called.
    %%   %% TODO: Check spelling on coalesced.

    %%   erlang:cancel_timer(Timer),

    %%   %% Processes all initial packets in order by calling 
    %%   %% handle_initial and buffers remaining packets.
    %%   handle_coalesced(Data, Packets);


    {initial, Data1, Packet, TLS_Record} ->
      ?DBG("Initial response received.~n", []),
      %% correct in order response. No need to buffer.
      
      %% Cancel timer since response was received.
      erlang:cancel_timer(Timer),
      
      %% Validates handshake and either keeps state to wait for more
      %% initial packets, or moves to handshake state.
      handle_initial(Data1, Packet, TLS_Record);
    
    {vx_neg, Versions} = Version_Neg ->
      ?DBG("Version Negotiation Packet Received.~n", []),
      
      %% Version negotiation is to be handled by the application.
      %% Send a reply to the caller.
      gen_statem:reply(Owner, {error, Version_Neg}),

      %% Cancel the timer and shutdown.
      erlang:cancel_timer(Timer),
      {stop, shutdown};
    
    {retry, New_Data0} ->
      ?DBG("Retry packet received.~n", []),

      %% The updated Conn should have the info to send a
      %% new correct initial packet.
      %% Parsed Data might have a crypto token included.
      erlang:cancel_timer(Timer),
      
      %% Reset the crypto information.
      New_Data = quic_crypto:crypto_init(New_Data0),

      %% Forms a new initial packet from the parsed retry packet and sends it.
      New_Data1 = send_and_form_packet(initial, New_Data),
      
      %% This resets the timeout attempt counter, but it keeps the
      %% same timeout length as the previous attempt.
      %% Might not be appropriate, but if a retry packet
      %% is received the next initial packet will probably
      %% succeed.
      Timer1 = erlang:start_timer(self(), Timeout,
                                  {initial_client, 1}),
      {keep_state, New_Data1};

    protected ->
      ?DBG("Protected packet received~n", []),
      %% Out of order packet received.
      %% Don't know how to decode it yet.
      %% Queue the packet on the buffer.

      %% Cancel timer since now the server will deal with
      %% ensuring reliability. Probably in kernel buffer anyways.
      erlang:cancel_timer(Timer),
      %% I'm appending the packet since it will need the handshake packet
      %% before it can be decoded and there might already be one in the buffer.
      {keep_state,
       Data#quic_data{
         buffer = Buffer ++ [{protected, Packet0}]}};
    
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
      %% Could be a parsing error or a decrypt error
      %% from the server.
      ?DBG("Quic error: ~p~n", [Reason]),

      %% A reply still needs to be sent to the owner.
      gen_statem:reply(Owner, {error, Reason}),

      %% Shutdown in this case too, for now.
      erlang:cancel_timer(Timer),
      {stop, shutdown}
  end;

init_client({timeout, connect}, Message, #quic_data{conn = Conn}) ->
  %% Timeout for entire connection handshake process.
  %% Also needs to be processed in the handshake_client state.
  %% Message is {error, timeout}
  {stop_and_reply, {Conn#quic_conn.owner, Message}}.


%% The handshake_client state is responsible for performing the
%% crypto handshake for the client. A validated handshake from the
%% server sends a handshake packet with the TLS FIN record.
%% Needs to end with a reply to the process owner.
%% First check if there are any handshake messages in the buffer to
%% process.
-spec handshake_client(Event, Message, Data) -> Result when
    Event :: internal |
             info,
    Message :: check_buffer |
               UDP_Message,
    UDP_Message :: {udp, Socket, Address, Port},
    Socket :: inet:socket(),
    Address :: inet:socket_address(),
    Port :: inet:port_number(),
    Data :: #quic_data{},
    Result :: keep_state_and_data |
              {keep_state, Data} |
              {next_state, protected, Data, Events} |
              {stop, shutdown},
    Events :: [{{timeout, connect}, infinity, any()} |
               {next_event, internal, check_buffer}];
                      %% Connection handshake timeout.
                      (Timeout, Message, Data) -> Result when
    Timeout :: {timeout, connect},
    Message :: {error, timeout},
    Data :: #quic_data{},
    Result :: {stop_and_reply, shutdown, {pid(), Message}}.

handshake_client(internal, check_buffer,
                 #quic_data{buffer = []} = Data) ->
  %% Nothing in the buffer to check
  keep_state_and_data;


handshake_client(internal, check_buffer,
                 #quic_data{buffer = Buffer0} = Data0) ->
  %% Something to check. Get all handshake packets from buffer and
  %% see if they finish the handshake process.
  %% handle_handshake will either transition to next state (protected)
  %% or keep state and wait for more handshake packets to arrive.
  case lists:keytake(handshake, 1, Buffer0) of
    
    false ->
      %% No handshake packets processed yet so wait for them.
      keep_state_and_data;
    
    {handshake, Raw_Packet, Buffer} ->
      %% Woohoo something to do already.
      {handshake, Data, Packet, TLS_Info} = 
        quic_crypto:parse_packet(Raw_Packet, Data0#quic_data{buffer = Buffer}),
        
      handle_handshake(Packet, Data, TLS_Info)
  end;

handshake_client(info, {udp, Socket, Address, Port, Packet0},
                #quic_data{conn = 
                             #quic_conn{socket = Socket,
                                        address = Address,
                                        port = Port,
                                        owner = Owner
                                       } = Conn0,
                           window_timeout = {Timer, Timeout},
                           buffer = Buffer
                          } = Data0) ->
  %% Packet from the correct socket, address, and port
  %% See if it's what we need.
  case quic_crypto:parse_packet(Packet0, Data0) of
    {handshake, Data, Packet, TLS_Info} ->
      %% Woohoo got a handshake packet.
      handle_handshake(Data, Packet, TLS_Info);

    protected ->
      %% out of order, queue it and repeat.
      {keep_state, 
       Data0#quic_data{buffer = Buffer ++ [{protected, Packet0}]}};
    
    %% {coalesced, Packets} ->
    %% Coalesced packets not implemented yet.
    %%   %% multiple packets were coalesced, call handle_coalesced to
    %%   %% handle each packet appropriately.
    %%   %% Either keeps state and waits for more packets or handles the
    %%   %% handshake packets and transitions to the protected state.
    %%   handle_coalesced(Data0, Packets);
    
    {initial, Data, Packet, TLS_Info} ->
      %% This could happen for out of order packets and late packet
      %% arrivals. If the packet number for this packet is less than
      %% that of the last processed initial packet, drop this one.
      %% Checked in handle_initial.
      handle_initial(Data, Packet, TLS_Info);
    
    {quic_error, Reason} ->
      %% Could be a parsing error or a decrypt error
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
  %% Message is {error, timeout}.
  {stop_and_reply, {Conn#quic_conn.owner, Message}}.


-spec init_server(Event, Message, Data) -> Result when
    Event :: {call, From},
    From :: pid(),
    Message :: {accept, Timeout},
    Timeout :: non_neg_integer(),
    Data :: #quic_data{},
    Result :: {next_state, handshake_server, Data, [Events]},
    Events :: {next_event, internal, rekey} |
              {{timeout, accept}, Timeout, {error, timeout}}.

init_server({call, From}, {accept, Timeout}, 
            #quic_data{conn = Conn} = Data0) ->
  %% Switch socket to active once since ownership is confirmed at
  %% this point.
  %% Note: Using {active, 1} here instead of {active, once}.
  %% This allows for {active, 1} to also be called in the handshake
  %% state and thus to expect 2 active receipts.
  ok = inet:setopts(Conn#quic_conn.socket, [{active, 1}]),
  
  %% retry and version negotiation packets are handled in quic_server
  %% Only a successful initial packet is being handled by this
  %% statem.
  %% Need to send an initial packet and handshake packet.
  %% Optional to send protected data. Will handle that later.
  %% Conn will not change. Data will change (packet numbers).
  %% Maybe have this return an unencrypted packet so that less work is performed.
  Data = send_and_form_packet(initial, Data0),
  
  %% Start 100 ms timer for resending packet(s).
  Timer = erlang:start_timer(100, {initial_server, 1}),

  %% Start handshake timer in state actions. Needs to be cancelled
  %% when handshake_server succeeds.
  {next_state, handshake_server,
   Data#quic_data{window_timeout = {Timer, 100}},
   [{next_event, internal, rekey},
    {{timeout, accept}, Timeout, {error, timeout}}]}.


%% The handshake_server state rekeys the server to the handshake keys
%% and sends the handshake packets as internal events before transitioning to
%% the await_finished state.
-spec handshake_server(Event, Message, Data) -> Result when
    Event :: info,
    Message :: {timeout, Timer_Ref, Timeout_Message} |
               UDP_Message,
    Timer_Ref :: reference(),
    Timeout_Message :: {initial_response, Attempt},
    Packet :: binary(),
    Attempt :: non_neg_integer(),
    UDP_Message :: {udp, Socket, Address, Port, Packet},
    Socket :: inet:socket(),
    Address :: inet:socket_address(),
    Port :: inet:port_number(),
    Data :: #quic_data{},
    Result :: keep_state_and_data |
              {keep_state, Data} |
              {next_state, protected, Data, Events} |
              {stop, shutdown},
    Events :: [{{timeout, accept}, infinity, any()} |
               {next_event, internal, check_buffer}];
                      %% Accept handshake timeout clause.
                      (Timeout, Message, Data) -> Result when
    Timeout :: {timeout, accept},
    Message :: {error, timeout},
    Data :: #quic_data{},
    Result :: {stop_and_reply, shutdown, {pid(), Message}}.

handshake_server(internal, rekey, Data0) ->
  %% Rekey the server to the handshake keys.
  Data = quic_crypto:rekey(Data0),
  {keep_state, Data, [{next_event, internal, encrypted_exts}]};

handshake_server(internal, encrypted_exts, Data0) ->
  %% Send the encrypted extensions packet
  Data = send_and_form_packet(encrypted_exts, Data0),
  {keep_state, Data, [{next_event, internal, certificate}]};

handshake_server(internal, certificate, Data0) ->
  %% Send the certificates packet
  Data = send_and_form_packet(certificate, Data0),
  {keep_state, Data, [{next_event, internal, cert_verify}]};

handshake_server(internal, cert_verify, Data0) ->
  %% Send the certificate verify packet
  Data = send_and_form_packet(cert_verify, Data0),
  {keep_state, Data, [{next_event, internal, finished}]};

handshake_server(internal, finished, Data0) ->
  %% Send the server finished packet
  Data1 = send_and_form_packet(finished, Data0),
  %% Server has all the info needed to finish rekeying to protected state.
  Data2 = quic_crypto:rekey(Data1),
  %% keep_state until client's finished is received.
  {next_state, await_finished, Data2}.


%% The await_finished state is waiting for the client's finished packet
%% before transitioning into the protected state.
%% Packets can be sent with full protection in this state.
await_finished(info, {udp, Socket, Address, Port, Packet0},
               #quic_data{conn =
                            #quic_conn{socket = Socket,
                                       address = Address,
                                       port = Port},
                          window_timeout = {Ref, Timeout},
                          buffer = Buffer
                         } = Data0) ->
  %% Packet received, Check if it's the one we want.
  case quic_crypto:parse_packet(Packet0, Data0) of
    {initial, Data, Packet, TLS_Info} ->
      %% Initial packet here either is a repeat of the client
      %% handshake, initial early client traffic, or an ack.
      %% handle_initial covers these.
      handle_initial(Data, Packet, TLS_Info);

    {handshake, Data, Packet, TLS_Info} ->
      %% This handshake message should contain the correct handshake
      %% Message so check it. Either will be valid and move to
      %% protected state or invalid and stop.
      handle_handshake(Data, Packet, TLS_Info);
    
    {protected, Data, Packet, TLS_Info} ->
      %% We still need the finished packet, but we can handle this information now.
      handle_protected(Data, Packet, TLS_Info);
    
    _Other ->
      %% Everything else is a failure.
      keep_state_and_data
  end;

%% TODO: Timeouts need to be moved and created.
await_finished(info, {timeout, _Ref, {initial_response, Attempt}},
               #quic_data{
                  conn = Conn,
                  window_timeout = {_Ref, Timeout}
                 } = Data0) ->
  %% Timeout so resend.
  %% The packet numbers will change again.
  Data = send_and_form_packet(initial_response, Data0),

  %% Double timeout window.
  Timer = erlang:start_timer(self(), Timeout * 2,
                             {initial_response, Attempt + 1}),
  
  {keep_state,
   Data#quic_data{window_timeout = {Timer, Timeout * 2}}};        

%% I think this should probably be cancelled earlier.
await_finished({timeout, accept}, Message, 
               #quic_data{conn=Conn}) ->
  %% Accept timeout. Message is {error, timeout}
  {stop_and_reply, {Conn#quic_conn.owner, Message}}.


handle_event(info, {udp_passive, Socket}, 
             #quic_data{conn = #quic_conn{socket = Socket}}) ->
  %% Maintains the connection in an {active, once} state while
  %% the connection handshake is being performed.
  %% After the handshake is successful, the socket is
  %% maintained in an active, true state and this shouldn't
  %% be called.
  ok = inet:setopts(Socket, [{active, once}]),
  keep_state_and_data;

%% I think these should actually be ignored.
%% handle_event(info, {timeout, _Ref, {State, _}}, 
%%              #quic_data{conn = Conn,
%%                         window_timeout = {_Ref, _Time}}) ->
%%   %% Complete timeout.
%%   %% Reply needs to be sent to the owning process.
%%   gen_statem:reply(Conn#quic_conn.owner, {error, timeout}),
%%   {stop, shutdown};

handle_event(info, _, _) ->
  %% Ignore all other event info messages that occur.
  %% Includes stray udp packets from a different IP and/or Port.
  %% TCP messages, Messages that don't make sense from procs, etc.
  keep_state_and_data.


%% First need to verify that the TLS_Info is valid and not a repeat.
%% Transitions to handshake state when valid.
%% Exits when invalid.
%% TODO: Handle early client traffic here.
handle_initial(#quic_data{
                  type = client,
                  recv = Recv0, 
                  conn = Conn
                 } = Data0, 
               Packet, TLS_Info) ->
  
  case quic_crypto:validate_tls(Data0, TLS_Info) of
    {valid, Data} ->
      %% Successful case.
      Recv = handle_recv(Recv0, Packet, Conn#quic_conn.socket),
      {next_state, handshake_client, Data#quic_data{recv = Recv0}};
    
    repeat ->
      %% Already processed this data.
      keep_state_and_data;

    Other ->
      {stop_and_reply, {Conn#quic_conn.owner, Other}}
  end;

handle_initial(#quic_data{
                  type = server,
                  recv = Recv0, 
                  conn = Conn
                 } = Data0, 
               Packet, TLS_Info) ->
  
  case quic_crypto:validate_tls(Data0, TLS_Info) of
    {valid, Data} ->
      %% Successful case.
      Recv = handle_recv(Recv0, Packet, Conn#quic_conn.socket),
      {next_state, handshake_server, Data#quic_data{recv = Recv0}};
    
    repeat ->
      %% Already processed this data.
      keep_state_and_data;
    
    Other ->
      {stop_and_reply, {Conn#quic_conn.owner, Other}}
  end.


handle_handshake(#quic_data{
                    type = client,
                    recv = Recv0, 
                    conn = Conn
                   } = Data0, 
                 Packet, TLS_Info) ->
  
  case quic_crypto:validate_tls(Data0, TLS_Info) of
    {valid, Data} ->
      %% Done with handshake state.
      Recv = handle_recv(Recv0, Packet, Conn#quic_conn.socket),
      %% TODO: Add send fin message event.
      {next_state, protected, Data#quic_data{recv = Recv}};
    {incomplete, Data} ->
      %% Not done yet
      Recv = handle_recv(Recv0, Packet, Conn#quic_conn.socket),
      {keep_state, Data#quic_data{recv = Recv}};

    Other ->
      %% Invalid for some reason
      %% reply and stop
      {stop_and_reply, {Conn#quic_conn.owner, Other}}
  end.


handle_protected(Data, Packet, TLS_Info) ->
  %% Routes the Packet data to the correct stream.
  %% Stream gen_servers are referenced by the {Socket, StreamID} pair.
  %% Updates quic connection data and limits from max_data frames and others.
  %% If a crypto frame with a TLS rekey message is received, updates the
  %% keys and ivs of the client and server.
  
  

  ok.
  


-spec send_and_form_packet(Pkt_Type, Data) -> Data when
    Pkt_Type :: initial |
                encrypted_exts |
                certificate |
                cert_verify |
                finished |
                protected,
    Data :: #quic_data{}.
%% Crashes when packet cannot be created.

send_and_form_packet(Pkt_Type, Data0) ->
  case quic_crypto:form_packet(Pkt_Type, Data0) of
    %% {ok, Data, Packets} when is_list(Packets) ->
    %% Coalesced packets Not implemented yet.
    %%   %% The packets could not be completely coalesced so we have to
    %%   %% fold over the list of packets and send each one.
    %%   %% ok as Acc ensures all are sent correctly
    %%   ok = lists:foldl(fun(Packet, ok) -> do_send(Conn, Packet) end,
    %%                    ok, Packets),
    %%   Data;

    {ok, Data, Packet} ->
      %% The packets were coalesced so there is only one packet
      %% to send.
      ok = do_send(Data#quic_data.conn, Packet),
      Data

      %% Crash on any other case.
  end.

-spec do_send(Conn, Packet) -> ok | {error, Reason} when
    Conn :: #quic_conn{},
    Packet :: binary(),
    Reason :: gen_quic:errors().

%% Wrapper function around prim_inet.
%% TODO: Check prim_inet:sendto args. Might need a non_neg length.
do_send(#quic_conn{
           socket = Socket,
           address = Address,
           port = Port
          },
        Packet) ->
  prim_inet:sendto(Socket, Address, Port, Packet).


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


-spec get_recv_state(Owner, Options) -> Recv_State when
    Owner :: pid(),
    Options :: [Option],
    Option :: gen_quic:option(),
    Recv_State :: {active, Owner} |
                  {active, Owner, N} |
                  {[Packet], [Packet]},
    N :: non_neg_integer(),
    Packet :: binary() | list().

get_recv_state(Owner, Options) ->

  case inet_quic_util:get_opt(Options, active) of
    false ->
      %% Not defined in options.
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
%% TODO: Add support for binary() -> list() here.
%% Also need to add initialization option for it in get_recv_state/2
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
  {Next, [Data | Rest]};

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

