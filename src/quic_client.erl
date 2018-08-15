%%%-------------------------------------------------------------------
%%% @author Alex Misch <alex@alex-Lenovo>
%%% @copyright (C) 2018, Alex Misch
%%% @doc
%%% Callback functions for the client statem.
%%% @end
%%% Created :  7 Aug 2018 by Alex Misch <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_client).

-behaviour(gen_statem).

%% See quic_conn for the API.
%% State functions.
-export([initial/3]).
-export([handshake/3]).
-export([connected/3]).

%% gen_statem callbacks
-export([callback_mode/0, init/1, terminate/3, code_change/4]).

-include("quic_headers.hrl").


%%%===================================================================
%%% gen_statem callbacks
%%%===================================================================

-spec callback_mode() -> gen_statem:callback_mode_result().
callback_mode() -> state_functions.


-spec init([Args]) -> gen_statem:init_result(atom()) when
    Args :: Data | Options,
    Data :: #quic_data{},
    Options :: [Option],
    Option :: gen_quic:options().

init([#quic_data{
         type = client,
         conn = Conn
        } = Data0, Quic_Opts]) ->

  Params = quic_crypto:default_params(client, Quic_Opts),

  Recv = get_recv_state(Conn#quic_conn.owner, Quic_Opts),
  
  %% TODO: initialize the dest and src conn ids here.
  Data = Data0#quic_data{
           recv = Recv,
           ready = quic_staging:new(none),
           priority_num = 1,
           params = Params
          },

  {ok, initial, Data}.


initial({call, _From}, {connect, Address, Port, Timeout}, 
        #quic_data{
           conn = #quic_conn{
                     socket = Socket
                    } = Conn0
          } = Data0) ->
  %% Have control of socket.
  %% Make it active.
  ok = inset:setopts(Socket, [{active, true}]),
  
  Data1 = quic_crypto:crypto_init(Data0),

  %% Set timeout for entire connect.
  %% Keep state, but add internal event for timeout
  %% Cast {accept, LSocket} to enter initial receive loop
  gen_statem:cast(self(), {connect, Address, Port}),
  
  Data2 = Data1#quic_data{
            conn = Conn0#quic_conn{
                     address = Address,
                     port = Port
                    }
           },

  {keep_state, Data2, [{{timeout, accept}, Timeout, {error, timeout}}]};

%% This is a cast so that the state machine can cast to itself to repeat the
%% state without preventing timeouts and other messages like next_event would.
initial(cast, {connect, _Address, _Port}, Data0) ->
  
  %% Create and send the client_hello message.
  Data = send_and_form_packet(client_hello, Data0),
  
  {keep_state, Data};

initial(info, {udp, Socket, Address, Port, Packet},
       #quic_data{
          conn = #quic_conn{
                    socket = Socket,
                    address = Old_Address,
                    port = Old_Port
                   } = Conn0
         } = Data0) ->

  %% At this stage, the Port will probably change and the address might change
  %% As the server opens a different socket from the listening socket.
  
  Data1 = Data0#quic_data{
           conn = Conn0#quic_conn{
                    address = Address,
                    port = Port
                   }
          },
  
  case quic_crypto:parse_packet(Packet, Data1) of
    {retry, New_Data0} ->
      %% received a retry packet.
      %% Rekey the crypto
      New_Data1 = quic_crypto:init_crypto(New_Data0),
      %% Send a new client_hello derived from the new information.
      New_Data2 = send_and_form_packet(client_hello, New_Data1),
      {keep_state, New_Data2};
    
    Packets when is_list(Packets) ->
      %% Cast the handling of each packet to itself, keep the last data.
      Data2 = lists:foldl(
                fun({Type, {Data, Frames, TLS_Info}}, _Acc) ->
                    %% When we can Decrypt it.
                    gen_statem:cast(self(), {handle, Type, Frames, TLS_Info, 
                                             {connect, Old_Address, Old_Port}}),
                    Data;
                   (Encrypted, Data) ->
                    %% When we cannot decrypt it.
                    gen_statem:cast(self(), {handle_encrypted, Encrypted}),
                    Data
                end, Data1, Packets),
      {keep_state, Data2};

    _Other ->
      %% Could be a stray UDP packet or an invalid quic packet.
      %% Just repeat process.
      keep_state_and_data
  end;
    
initial(cast, {handle, initial, Frames, TLS_Info, Event} = Message, Data0) ->
  case quic_crypto:validate_tls(Data0, TLS_Info) of
    {invalid, Reason} ->
      %% This is a stopping condition for the client
      {keep_state_and_data, 
       [{next_event, internal, {protocol_violation, Reason}}]};

    {valid, Data1} ->
      %% Successful validation of server_hello
      %% Send an acknowledgement back.
      Data2 = send_and_form_packet(initial, Data1),
      %% Handle any frames including acks.
      Data3 = handle_frames(Data2, Frames),
      
      {next_state, handshake, Data3,
       [{next_event, internal, rekey}]};
    
    out_of_order ->
      %% When there are multiple initial server messages and they arrived out of
      %% order. Re-cast the message and process others.
      gen_statem:cast(self(), Message),
      keep_state_and_data;
    
    {incomplete, Data1} ->
      %% The server_hello can fit into more than packet, so keep state and wait for
      %% more.
      Data2 = handle_frames(Data1, Frames),
      {keep_state, Data2}
  end;

initial(cast, {handle_encrypted, _Encrypted}, _Data) ->
  %% Everything that cannot be unencrypted yet gets pushed to next state.
  {keep_state_and_data, [postpone]};

initial(internal, {protocol_violation, _Event},
        #quic_data{
           conn = #quic_conn{
                     owner = Owner
                    }
          }) ->
  %% TODO: Respond to server with error code.
  {stop_and_reply, {Owner, protocol_violation}};

initial({timeout, accept}, {error, timeout}, #quic_data{conn = Conn}) ->
  %% Accept timed out. Send back failure response and exit
  {stop_and_reply, {Conn#quic_conn.owner, {error, timeout}}}.


handshake(internal, rekey, Data0) ->
  %% Rekey to handshake keys
  Data = quic_crypto:rekey(Data0),
  {keep_state, Data};

handshake(cast, {handle_encrypted, 
                 {Type, _Old_Data, Header, Pkt_Num, Enc_Frames}}, 
          Data0) ->
  %% Try and decrypt the packet with the new Data.
  New_Packet = {Type, Data0, Header, Pkt_Num, Enc_Frames},
  case quic_crypto:decrypt_and_parse(New_Packet) of
    New_Packet ->
      %% Could not decrypt it yet. Postpone to next state.
      {keep_state_and_data, [postpone]};
    
    {Type, {Data1, Frames, TLS_Info}} ->
      %% Successful decryption and parsing.
      gen_statem:cast(self(), {handle, Type, Frames, TLS_Info}),
      {keep_state, Data1}
  end;

handshake(cast, {handle, handshake, Frames, TLS_Info} = Message, 
          Data0) ->
  %% validate_tls checks for ordering of the packets. If out of order,
  %% re-cast {check, Frames, TLS_Info} to be processed again later.
  case quic_crypto:validate_tls(Data0, TLS_Info) of
    {incomplete, Data1} ->
      %% This is when the right TLS message was processed, but more are needed
      %% for the handshake state.
      Data2 = handle_frames(Data1, Frames),
      {keep_state, Data2};
    
    {valid, Data1} ->
      %% This is when the handshake state has processed all the tls packets it needs
      Data2 = handle_frames(Data1, Frames),
      %% Need to send the client's finished message.
      Data3 = send_and_form_packet(finished, Data2),
      
      {next_state, connected, Data3,
       [{next_event, internal, rekey},
        {next_event, internal, success}]};

    out_of_order ->
      %% Re-cast out of order messages until they are handled in order.
      gen_statem:cast(self(), Message),
      keep_state_and_data;
    
    {invalid, Reason} ->
      {keep_state_and_data, [{next_event, internal, {protocol_violation, Reason}}]}
  end;

handshake(info, {udp, Socket, Address, Port, Raw_Packet}, 
          #quic_data{
             conn = #quic_conn{
                       socket = Socket,
                       address = Address,
                       port = Port
                      }
            } = Data0) ->
  %% Received back a packet at some point in this state.
  %% Decrypt it and see what it is.
  case quic_crypto:parse_packet(Raw_Packet, Data0) of
    [{invalid, Reason}] ->
      {keep_state_and_data, [{next_event, internal, {protocol_violation, Reason}}]};

    Packets when is_list(Packets) ->
      Data1 = lists:foldl(
                fun({Type, {Data, Frames, TLS_Info}}, _Acc) ->
                    %% When we can Decrypt it.
                    gen_statem:cast(self(), {handle, Type, Frames, TLS_Info}),
                    Data;
                   (Encrypted, Data) ->
                    %% When we cannot decrypt it.
                    gen_statem:cast(self(), {handle_encrypted, Encrypted}),
                    Data
                end, Data0, Packets),
      {keep_state, Data1};

    _Other ->
      %% Ignore it if we do.
      keep_state_and_data
  end.

%% We made it. First rekey then respond to owner that connection was successful 
%% and cancel connect timeout.
%% TODO: clean up the crypto stuff in Data. We don't need everything anymore.
connected(internal, rekey, Data0) ->
  %% rekey to application/1-RTT protected state
  Data = quic_crypto:rekey(Data0),
  {keep_state, Data};

connected(internal, success, 
          #quic_data{
             conn = #quic_conn{
                       socket = Socket,
                       owner = Owner
                      }
            }) ->
  %% Need to reply to owner since this was started with a call.
  gen_statem:reply(Owner, {ok, Socket}),
  %% Setting timeout on the timer to infinity cancels the timer.
  %% Transition to internal event to clear buffer.
  {keep_state_and_data, [{{timeout, connect}, infinity, none}]};

connected(cast, {send, Frame}, Data0) ->
  %% Stage frames to be sent when ready.
  Data = quic_staging:enstage(Data0, Frame),
  {keep_state, Data};

connected(cast, {send_n_packets, N, RTO}, 
          #quic_data{window_timeout = Win} = Data0) ->
  %% Remote process will keep track of congestion control and when to send packets.
  %% This enters a destage and send loop
  %% Update the RTO timeout.
  Data = Data0#quic_data{window_timeout = Win#{rto := RTO}},
  
  {keep_state, Data, [{next_event, internal, {send, N}}]};

connected(internal, {send, 0}, _Data) ->
  %% Base Case of the send n loop when there are enough packets to send.
  keep_state_and_data;

connected(internal, {send, N}, 
          #quic_data{ready = Staging0} = Data0) ->
  %% Destage a list of frames from Data, if available.
  %% send and form the packet, which sets a RTO timeout.
  %% recurse on N-1
  case quic_staging:destage(Staging0) of
    empty ->
      %% Nothing to send so don't recurse.
      keep_state_and_data;
    
    {Staging, Frames, Size} ->
      %% Something to send.
      Data1 = Data0#quic_data{ready = Staging},
      Data2 = send_and_form_packet({short, Frames}, Data1),
      {keep_state, Data2, [{next_event, internal, {send, N-1}}]}
  end;

connected(cast, {handle_encrypted, {Type, _Old_Data, Header, Pkt_Num, Enc_Frames}},
          Data0) ->

  New_Packet = {Type, Data0, Header, Pkt_Num, Enc_Frames},

  case quic_crypto:decrypt_and_parse(New_Packet) of
    New_Packet ->
      %% This might happen if the crypto rekey message has not been received yet.
      gen_statem:cast(self(), {handle_encrypted, New_Packet}),
      keep_state_and_data;
    
    {Type, Data1, Frames, TLS_Info} ->
      gen_statem:cast(self(), {handle, Type, Frames, TLS_Info}),
      {keep_state, Data1}
  end;

connected(cast, {handle, _Type, Frames, TLS_Info}, Data0) ->
  %% Check if there is anything to update from tls_info.
  case quic_crypto:validate_tls(Data0, TLS_Info) of
    no_change ->
      Data1 = handle_frames(Data0, Frames),
      {keep_state, Data1};
    
    {valid, Data1} ->
      Data2 = handle_frames(Data1, Frames),
      {keep_state, Data2, [{next_event, internal, rekey}]};
    
    {invalid, Reason} ->
      {keep_state_and_data, [{next_event, internal, {protocol_violation, Reason}}]}
  end;

connected(info, {udp, Socket, IP, Port, Raw_Packet},
          #quic_data{
             conn = #quic_conn{
                       socket = Socket,
                       address = IP,
                       port = Port
                      }
            } = Data0) ->
  %% Received a packet.
  %% Decrypt and Parse it.
  case quic_crypto:parse_packet(Raw_Packet, Data0) of    
        [{invalid, Reason}] ->
      {keep_state_and_data, [{next_event, internal, {protocol_violation, Reason}}]};

    Packets when is_list(Packets) ->
      Data1 = lists:foldl(
                fun({Type, {Data, Frames, TLS_Info}}, _Acc) ->
                    %% When we can Decrypt it.
                    gen_statem:cast(self(), {handle, Type, Frames, TLS_Info}),
                    Data;
                   (Encrypted, Data) ->
                    %% When we cannot decrypt it.
                    gen_statem:cast(self(), {handle_encrypted, Encrypted}),
                    Data
                end, Data0, Packets),
      {keep_state, Data1};

    Other ->
      %% Ignore it for now.
      io:format("Error decrypting and parsing in connected state: ~p~n", [Other]),
      keep_state_and_data
  end;

connected(internal, {protocol_violation, _Reason},
         #quic_data{
            conn = #quic_conn{
                      owner = Owner
                     }
           }) ->
  %% TODO: send appropriate error to client.
  %% TODO: send better error to owner.
  {stop_and_reply, {Owner, protocol_violation}};

connected(info, {udp, _, _, _, _}, _Data) ->
  %% Received a udp message from somewhere else.
  %% Ignore it.
  keep_state_and_data;

connected({timeout, idle}, _, 
          #quic_data{
             conn = #quic_conn{
                       owner = Owner
                      }
            }) ->
  %% TODO: Idle timeout not implemented yet.
  %% Will be set in this state though.
  %% TODO: send response to client.
  {stop_and_reply, {Owner, idle_timeout}}.

%% This should just be imported from quic_conn.
send_and_form_packet(Packet_Type, Data) ->
  quic_conn:send_and_form_packet(Packet_Type, Data).


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

%% Not used at the moment, might be used in the future and moved to quic_conn.
%% %% handle_recv either queues parsed data and returns 
%% %% {List, List} or sends the packet to the owner and 
%% %% returns an updated recv state.
%% %% TODO: Add support for binary() -> list() here.
%% %% Also need to add initialization option for it in get_recv_state/2
%% -spec handle_recv(Recv_State, Data, Socket) -> Recv_State when
%%     Recv_State :: {[Data], [Data]} |
%%                   {active, Owner} |
%%                   {active, Owner, non_neg_integer()},
%%     Data :: binary() | #quic_stream{},
%%     Socket :: gen_quic:socket(),
%%     Owner :: pid().

%% handle_recv(Recv, <<>>, _Socket) ->
%%   %% This clause is to make logic of handling 0-RTT data more smooth.
%%   %% Obviously if there is no data to handle, there's nothing to do.
%%   Recv;

%% handle_recv({[], []}, Data, _Socket) ->
%%   {[Data], []};

%% handle_recv({[], Items}, Data, _Socket) ->
%%   {lists:reverse([Data | Items]), []};

%% handle_recv({Next, Rest}, Data, _Socket) ->
%%   {Next, [Data | Rest]};

%% handle_recv({active, Owner}, Data, Socket) ->
%%   Owner ! {quic, Socket, Data},
%%   {active, Owner};

%% handle_recv({active, Owner, N}, Data, Socket) when N > 1 ->
%%   Owner ! {quic, Socket, Data},
%%   {active, Owner, N-1};

%% handle_recv({active, Owner, 1}, Data, Socket) ->
%%   Owner ! {quic, Socket, Data},
%%   Owner ! {quic_passive, Socket},
%%   {[], []}.


%% Calls out to the shared function handle_frame in quic_conn.
%% Either sends the frame to the correct process or modifies limits/timeouts
%% in Data.
handle_frames(Data, []) ->
  Data;

handle_frames(Data, Frames) ->
  lists:foldl(fun quic_conn:handle_frame/2, Data, Frames).


