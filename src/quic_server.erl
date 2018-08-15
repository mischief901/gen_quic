%%%-------------------------------------------------------------------
%%% @author Alex Misch <alex@alex-Lenovo>
%%% @copyright (C) 2018, Alex Misch
%%% @doc
%%% Separate server statem for the connection.
%%% @end
%%% Created :  7 Aug 2018 by Alex Misch <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_server).

-behaviour(gen_statem).

%% See quic_conn for the API.
%% State functions.
-export([initial/3]).
-export([handshake/3]).
-export([await_finished/3]).
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
         type = server,
         conn = Conn
        } = Data0, Quic_Opts]) ->

  Params = quic_crypto:default_params(server, Quic_Opts),
  
  Recv = get_recv_state(Conn#quic_conn.owner, Quic_Opts),
  
  Data = Data0#quic_data{
           recv = Recv,
           params = Params,
           priority_num = 1,
           ready = quic_staging:new(none)
          },

  {ok, initial, Data}.


initial({call, _From}, {accept, LSocket, Timeout}, _Data) ->
  %% Have control of socket.
  %% Set timeout for entire accept.
  %% Keep state, but add internal event for timeout
  %% Cast {accept, LSocket} to enter initial receive loop
  gen_statem:cast(self(), {accept, LSocket}),
  {keep_state_and_data, [{{timeout, accept}, Timeout, {error, timeout}}]};

%% This is a cast so that the state machine can cast to itself to repeat the
%% state without preventing timeouts and other messages like next_event would.
initial(cast, {accept, LSocket},
        #quic_data{
           conn = Conn0
          } = Data0) ->
  %% Poll every 50 milliseconds for a new packet.
  case prim_inet:recv(LSocket, 1, 50) of
    {error, timeout} ->
      %% Nothing received so repeat state and event.
      gen_statem:cast(self(), {accept, LSocket}),
      keep_state_and_data;
    
    {ok, {IP, Port, Packet}} ->
      %% Received a packet. Parse the header to get the initial crypto info.
      Conn = Conn0#quic_conn{
               address = IP,
               port = Port
              },
      
      case quic_crypto:parse_packet(Packet, Data0#quic_data{conn = Conn}) of
        %% TODO: Retry packets.
        %% {invalid, Data} ->
        %%   %% Send a retry packet.
        %%   {ok, Data, Packet} = quic_packet:form_packet(retry, Data),
        %%   %% Send over the new socket so the retry data is not lost.
        %%   prim_inet:sendto(Socket, IP, Port, Packet),

        %%   gen_statem:cast(self(), {accept, Socket}),
        %%   keep_state_and_data;

        {unsupported, Data} ->
          %% Need to send a version negotiation packet
          {ok, _Data, Vx_Neg_Packet} = quic_packet:form_packet(vx_neg, Data),
          prim_inet:sendto(LSocket, IP, Port, Vx_Neg_Packet),
          %% Recurse and try again.
          gen_statem:cast(self(), {accept, LSocket}),
          %% Do not change the data
          keep_state_and_data;
        
        [{initial, {Data, Frames, TLS_Info}}] ->
          %% Received and was able to parse the packet.
          %% handle_initial will either fail and restart the accept or
          %% succeed and move to handshake state.
          %% {accept, LSocket} is the current event to restart.
          %% Maybe move to something like this.
          {keep_state, Data,
           [{next_event, cast, {handle, initial, Frames, TLS_Info, {accept, LSocket}}}]};
        
        _Other ->
          %% Could be a stray UDP packet or an invalid quic packet.
          %% Just repeat process.
          gen_statem:cast(self(), {accept, LSocket}),
          keep_state_and_data
      end;
    
    _Other ->
      %% Ignore other socket messages.
      gen_statem:cast(self(), {accept, LSocket}),
      keep_state_and_data
  end;

initial(internal, {protocol_violation, _Event}, _Data) ->
  %% TODO: Respond to client with error code.
  keep_state_and_data;

initial({timeout, accept}, {error, timeout}, #quic_data{conn = Conn}) ->
  %% Accept timed out. Send back failure response and exit
  {stop_and_reply, {Conn#quic_conn.owner, {error, timeout}}};

initial(cast, {handle, initial, Frames, TLS_Info, Event}, Data0) ->
  case quic_crypto:validate_tls(Data0, TLS_Info) of
    {invalid, _Reason} ->
      %% Depending on reason, should send hello_retry_request, but
      %% that isn't implemented yet, so just repeat waiting for a valid packet.
      gen_statem:cast(self(), Event),
      keep_state_and_data;
    
    {valid, Data1} ->
      %% Successful validation of client_hello
      Data2 = send_and_form_packet(initial, Data1),

      %% Cast a message to self to send the handshake packets.
      %% This makes it easier to re-send missing packets.
      gen_statem:cast(self(), encrypted_exts),
      gen_statem:cast(self(), certificate),
      gen_statem:cast(self(), cert_verify),
      gen_statem:cast(self(), finished),

      Data3 = handle_frames(Data2, Frames),

      {next_state, handshake, Data3,
       [{next_event, internal, rekey}]};
    
    {incomplete, _} ->
      %% The client_hello must fit in a single packet.
      %% TODO: internal, protocol_violation event responds to client with error code.
      %% Then repeat accept.
      {keep_state_and_data, 
       [{next_event, internal, protocol_violation},
        {next_event, cast, Event}]}
  end.


handshake(internal, rekey, Data0) ->
  %% Rekey to handshake keys
  Data = quic_crypto:rekey(Data0),
  {keep_state, Data};

handshake(cast, finished, Data0) ->
  %% send the finished packet and transition to the await_finished state.
  Data = send_and_form_packet(finished, Data0),
  
  {next_state, await_finished, Data,
   [{next_event, internal, rekey}]};

handshake(cast, Pkt_Type, Data0) ->
  %% Forms and sends the handshake TLS Messages, except finished (above).
  %% There's no state change for forming these.
  Data = send_and_form_packet(Pkt_Type, Data0),
  {keep_state, Data};

handshake(info, {udp, Socket, IP, Port, _Raw_Packet}, 
          #quic_data{
             conn = #quic_conn{
                       socket = Socket,
                       address = IP,
                       port = Port
                      }
            }) ->
  %% Received back a packet from the correct location.
  %% Postpone processing this packet until the next state.
  %% Postponing is not necessary, but it does make the state machine easier to
  %% reason about.
  {keep_state_and_data, [postpone]};

handshake(info, _Other, _Data) ->
  %% Received a message from somewhere else
  %% do nothing.
  keep_state_and_data.


  %% case quic_crypto:parse_packet(Raw_Packet, Data0) of
  %%   {initial, Data, Frames, #tls_record{type = undefined}} ->
  %%     %% The client's ack of our server_hello.
  %%     %% TODO: Handling frame data.
  %%     %% handle_frames will cancel timers for any ack frames that are in frames.
  %%     Data1 = handle_frames(Data, Frames),
  %%     {keep_state, Data1};
    
  %%   {early_data, Data, Frames} ->
  %%     %% 0-RTT early data from client
  %%     %% TODO: Not Implemented Yet.
  %%     Data1 = handle_frames(Data, Frames),
  %%     {keep_state, Data1};
    
  %%   {handshake, Data, Frames, #tls_record{type = undefined}} ->
  %%     %% Acks for sent handshake packets.
  %%     Data1 = handle_frames(Data, Frames),
  %%     {keep_state, Data1};
    
  %%   _Other ->
  %%     %% We should not be getting anything outside these three ranges.
  %%     %% Ignore it if we do. Client cannot have all the information yet since
  %%     %% Server is still in handshake state.
  %%     %% TODO: Protocol violation?
  %%     keep_state_and_data
  %% end.

await_finished(internal, rekey, Data0) ->
  %% rekey to application/1-RTT protected state
  Data = quic_crypto:rekey(Data0),
  %% wait for either a client finished or timeout message.
  {keep_state, Data};

await_finished(info, {timeout, Ref, {Pkt_Type, _Pkt_Num, Timeout} = Message},
               #quic_data{
                  window_timeout = #{rto := RTO} = Win0
                 } = Data0) when is_map_key(Ref, Win0) ->
  %% The timeout for the packet fired and data indicates it has not been deleted.
  %% Form a new one and send it again.
  %% TODO: New RTT calculations.

  Win = maps:remove(Message, Win0),

  New_RTO = if
              Timeout < RTO ->
                %% The RTO has already been increased since this timeout fired.
                RTO;
              true ->
                %% The RTO needs to be increased
                RTO * 2
            end,

  Data = send_and_form_packet(Pkt_Type, Data0#quic_data{
                                          window_timeout = Win#{rto := New_RTO}}),
  {keep_state, Data};

await_finished(info, {timeout, _Ref, _Message}, _Data) ->
  %% Race condition clause.
  %% The packet was acknowledged and removed from window_timeout, 
  %% but the timer had already fired before cancelled.
  %% Ignore it.
  keep_state_and_data;

await_finished(info, {udp, Socket, IP, Port, Raw_Packet},
               #quic_data{
                  conn = #quic_conn{
                            socket = Socket,
                            address = IP,
                            port = Port
                           }
                 } = Data0) ->
  %% Received a packet from the correct IP:Port combo.
  case quic_crypto:parse_packet(Raw_Packet, Data0) of
    Packets when is_list(Packets) ->
      %% Have a list of parsed packets, cast each to be handled.
      %% The last Data has the cummulation of all the acks and other info from the
      %% coalesced packet. (If it's coalesced).
      Data1 = lists:foldl(fun({Type, {Data, Frames, TLS_Info}}, _Acc) -> 
                             gen_statem:cast(self(), {handle, Type, Frames, TLS_Info}),
                             Data
                         end,
                         [], Packets),
      
      {keep_state, Data1};
    
    %% Error conditions
    Other ->
      %% Something else happened.
      %%handle_error(Data0, Other)
      io:format("Other received when parsing await finished: ~p~n", [Other]),
      keep_state_and_data %% For now.
  end;

await_finished(cast, {handle, short, _Frames, _TLS_Info}, _Data) ->
  %% We could handle this now, but I'm going to wait and handle it in
  %% the connected state.
  {keep_state_and_data, [postpone]};

await_finished(cast, {handle, _Type, Frames, TLS_Info},
               Data0) ->
  %% Handle everything else now.
  %% The only packet that will change the TLS_Info is the finished message from
  %% the client.
  case quic_crypto:validate_tls(Data0, TLS_Info) of
    {valid, Data1} ->
      %% This indicates the finished message from the client has been received
      %% and is valid.
      Data2 = handle_frames(Data1, Frames),
      {next_state, connected, Data2};
    
    {incomplete, Data} ->
      %% Haven't received the finished message yet.
      {keep_state, Data};
    
    {invalid, Reason} ->
      %% Send an error code and exit.
      {keep_state_and_data, [{next_event, internal, {protocol_violation, Reason}},
                             {next_event, internal, stop}]}
  end;

await_finished({timeout, accept}, {error, timeout}, 
               #quic_data{
                 conn = #quic_conn{
                          owner = Owner
                          }}) ->
  {stop_and_reply, normal, {Owner, {error, timeout}}}.


%% handle_handshake(#quic_data{conn = Conn} = Data0, Frames, TLS_Info, Event) ->
%%   case quic_crypto:validate_tls(Data0, TLS_Info) of
%%     {invalid, _Reason} ->
%%       {keep_state_and_data, [{next_event, internal, {protocol_violation, Event}}]};
    
%%     {valid, Data1} ->
%%       %% Everything in the handshake state is complete so move to the partial-connected state.
%%       Data2 = handle_frames(Data1, Frames),
%%       {next_state, connected, Data2, [{next_event, internal, success}]};
    
%%     {incomplete, Data1} ->
%%       %% We're still waiting on more handshake packets
%%       Data2 = handle_frames(Data1, Frames),
%%       {keep_state, Data2}
%%   end.

%% We made it. Now the server can send data, but first must respond to
%% owner that connection was successful and cancel accept timeout.
connected(internal, success, 
          #quic_data{
             conn = #quic_conn{
                       socket = Socket,
                       owner = Owner
                      }
            }) ->
  %% Need to reply to the owner. Everything has been inside a call so far.
  gen_statem:reply(Owner, {ok, Socket}),
  %% Setting timeout on the timer to infinity cancels the timer.
  %% Transition to internal event to clear buffer.
  {keep_state_and_data, [{{timeout, accept}, infinity, none}]};

connected(internal, rekey, Data0) ->
  %% update the current crypto stuff to next set of keys/ivs
  %% Not implemented yet.
  Data = quic_crypto:rekey(Data0),
  {keep_state, Data};

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
  case quic_staging:dequeue(Staging0) of
    empty ->
      %% Nothing to send so don't recurse.
      keep_state_and_data;
    
    {Staging, Frames, Size} ->
      %% Something to send.
      Data1 = Data0#quic_data{ready = Staging},
      Data2 = send_and_form_packet({short, Frames}, Data1),
      %% TODO: Add in pacing for the packet. erlang:sleep(10), or something.
      {keep_state, Data2, [{next_event, internal, {send, N-1}}]}
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
    Packets when is_list(Packets) ->
      %% Cast handling the packets to itself and keep the last data.
      Data1 = lists:foldl(fun({Type, {Data, Frames, TLS_Info}}, _Acc) -> 
                              gen_statem:cast(self(), {handle, Type, Frames, TLS_Info}),
                              Data;
                             (Encrypted, Data) ->
                              %% The client initiated a tls rekey and we haven't
                              %% acted on it yet. This is the only time the server
                              %% might be unable to decrypt the packet.
                              gen_statem:cast(self(), {handle_encrypted, Encrypted}),
                              Data
                          end,
                          [], Packets),
      
      {keep_state, Data1};
    
    %% Error conditions
    Other ->
      %% Something else happened.
      %%handle_error(Data0, Other)
      io:format("Error decrypting and parsing in connected: ~p~n", [Other]),
      keep_state_and_data %% For now.
  end;

connected(cast, {handle, _Type, Frames, TLS_Info},
          Data0) ->
  case quic_crypto:validate_tls(Data0, TLS_Info) of
    %% Most likely these packets will not contain a crypto frame.
    no_change ->
      Data1 = handle_frames(Data0, Frames),
      {keep_state, Data1};

    {valid, Data1} ->
      %% There was a crypto frame to process. Need to rekey to next keys/ivs
      Data2 = handle_frames(Data1, Frames),
      {keep_state, Data2, [{next_event, internal, rekey}]};
    
    {invalid, Reason} ->
      %% Some issue with the crypto frame.
      {keep_state_and_data, [{next_event, internal, {protocol_violation, Reason}}]}
  end;
%% Old stuff:
  %%   {early_data, Data1, Frames} ->
  %%     %% Receiving a couple early_data packets is allowable.
  %%     %% TODO: Maybe have a similar clause in partial_connected to handle
  %%     %%       Packets sent before the client rekeys.
  %%     Data2 = handle_frames(Data1, Frames),
  %%     {keep_state, Data2};
    
  %%   {handshake, Data1, Frames, TLS_Info} ->
  %%     %% Should be a repeat packet.
  %%     case quic_crypto:validate_tls(Data1, TLS_Info) of
  %%       repeat ->
  %%         %% It is a repeat packet.
  %%         %% Data changes since the packet still needs to be acked.
  %%         {keep_state, Data1};
        
  %%       _Other ->
  %%         %% If it is not a repeat, then this is an error since we already
  %%         %% received the client's finished message.
  %%         %% TODO: This needs better error code.
  %%         {keep_state, Data1, 
  %%          [{next_event, internal, {protocol_violation, connected}}]}
  %%     end;
    
  %%   {short, Data1, Frames, TLS_Info} ->
  %%     case quic_crypto:validate_tls(Data1, TLS_Info) of
  %%       no_change ->
  %%         Data2 = handle_frames(Data1, Frames),
  %%         {keep_state, Data1};
        
  %%       {valid, Data2} ->
  %%         %% Would be a key change initiated by the client.
  %%         Data3 = handle_frames(Data2, Frames),
  %%         {keep_state, Data2, [{next_event, internal, rekey}]};

  %%       _Other ->
  %%         %% TLS Protocol violation
  %%         %% TODO: better error handling here.
  %%         {keep_state, Data1,
  %%          [{next_event, internal, {protocol_violation, connected}}]}
  %%     end;
    
  %%   _Other ->
  %%     %% Should not receive anything else in this state.
  %%     {keep_state_and_date, 
  %%      [{next_event, internal, {protocol_violation, connected}}]}
  %% end;

connected(internal, {protocol_violation, Reason},
         #quic_data{
            conn = #quic_conn{
                      owner = Owner
                     }
           }) ->
  %% All protocol violations at this point will lead to a connection error.
  %% TODO: send appropriate error to client.
  %% TODO: send better error to owner.
  {stop_and_reply, {protocol_violation, Reason}, {Owner, protocol_violation}};

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


handle_frames(Data, []) ->
  %% Nothing to handle so just return Data.
  Data;

handle_frames(Data0, Frames) ->
  %% Fold over the frames and send them to the appropriate process or update data.
  %% quic_conn:handle_frame is shared by quic_client and quic_server so it's
  %% located in the quic_conn.
  lists:foldl(fun quic_conn:handle_frame/2, Data0, Frames).


send_and_form_packet(Pkt_Type, Data) ->
  quic_conn:send_and_form_packet(Pkt_Type, Data).


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

