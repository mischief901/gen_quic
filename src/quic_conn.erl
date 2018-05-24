%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%%
%%% @end
%%% Created : 20 May 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_conn).

-behaviour(gen_statem).

%% API
-export([connect/4, listen/2, accept/2]).
-export([send/2, recv/3]).
-export([close/1]).

-export([start_link/1]).

%% gen_statem callbacks
-export([callback_mode/0, init/1, terminate/3, code_change/4]).
-export([handle_event/4]).

-include("quic_headers.hrl").


%%%===================================================================
%%% API
%%%===================================================================

connect(Address, Port, Opts, Timeout) ->
  %% Start gen_statem process, state opening.
  ?DBG("Starting statem~n", []),
  {ok, Pid} = start_link(Opts),

  ?DBG("Connecting to ~p on port ~p~n", [Address, Port]),
  %% Try to connect the socket to the server.
  case call(Pid, {connect, Address, Port, Timeout}) of
    {ok, Socket} ->
      %% Associate the Socket with the gen_statem Pid.
      quic_db:add_conn(Socket, Pid),
      {ok, Socket};
    Error ->
      Error
  end.


listen(Port, Opts) ->
  ?DBG("Starting statem~n", []),
  %% Start the gen_statem process, state opening.
  {ok, Pid} = start_link(Opts),

  %% Transition to listen state.
  case call(Pid, {listen, Port}) of
    {ok, Socket} ->
      ?DBG("Listening on port ~p~n", [Port]),
      %% Associate the Socket with the gen_statem Pid.
      quic_db:add_conn(Socket, Pid),
      {ok, Socket};
    Error ->
      Error
  end.


accept(LSocket, Timeout) ->
  ?DBG("Waiting to accept.~n", []),
  %% Lookup statem pid for socket
  {ok, {LSocket, Server_Pid}} = quic_db:lookup(LSocket),

  case call(Server_Pid, {accept, Timeout}) of
    {ok, {new, Client_Socket, Pid}} ->
      ?DBG("New connection.~n", []),
      quic_db:add_conn(Client_Socket, Pid),
      %% perform version negotiation after receiving a request.
      %% Maybe add list of loaded version modules here?
      %% For now, just return client socket.
      %% case call(Pid, {vsn_neg}) of
      %%   ok ->
      %%     ?DBG("Version negotiation successful~n", []),
      %%     {ok, Client_Socket};
      %%   Error ->
      %%     Error
      %% end;

      {ok, Client_Socket};

    {ok, {existing, Client_Socket}} ->
      ?DBG("Reconnection from ~p:~p~n", [IP, Port]),
      %% TODO: change stuff related to reconnection
      %% For now just return the client socket.
      {ok, Client_Socket};

    Accept_Error ->
      Accept_Error
  end.


send(Socket, Data) ->
  ?DBG("Sending on Socket ~p, ~p~n", [Socket, Data]),
  %% lookup socket.
  {ok, {Socket, Pid}} = quic_db:lookup(Socket),
  call(Pid, {send, Data}).

recv(Socket, _Length, Timeout) ->
  %% Should not be called when socket is active.
  ?DBG("Receiving passive packet on Socket ~p~n", [Socket]),
  %% lookup socket.
  {ok, {Socket, Pid}} = quic_db:lookup(Socket),
  case call(Pid, {recv, Timeout}) of
    {ok, Packet} ->
      ?DBG("Received packet: ~p~n", [Packet]),
      {ok, Packet};
    Error ->
      ?DBG("Packet not received: ~p~n", [Error]),
      Error
  end.

%%--------------------------------------------------------------------
%% @doc
%% Creates a gen_statem process which calls Module:init/1 to
%% initialize. To ensure a synchronized start-up procedure, this
%% function does not return until Module:init/1 has returned.
%%
%% @end
%%--------------------------------------------------------------------
-spec start_link(Socket :: inet:socket()) ->
                    {ok, Pid :: pid()} |
                    ignore |
                    {error, Error :: term()}.

start_link(Opts) ->
  gen_statem:start_link(?MODULE, [Opts], []).

%%%===================================================================
%%% gen_statem callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Define the callback_mode() for this callback module.
%% @end
%%--------------------------------------------------------------------
-spec callback_mode() -> gen_statem:callback_mode_result().
callback_mode() -> handle_event_function.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_statem is started using gen_statem:start/[3,4] or
%% gen_statem:start_link/[3,4], this function is called by the new
%% process to initialize.
%% @end
%%--------------------------------------------------------------------
-spec init(Args :: term()) ->
              gen_statem:init_result(term()).

init([#quic_conn{opts=Opts}=Conn]) ->
  process_flag(trap_exit, false),
  {ok, connected, {Conn, #quic_packet{}, {[], []}}};

init([Opts]) ->
  process_flag(trap_exit, true),
  {ok, open, #quic_conn{opts=Opts}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called for every event a gen_statem receives.
%% @end
%%--------------------------------------------------------------------
-spec handle_event('enter',
                   OldState :: term(),
                   State :: term(),
                   Data :: term()) ->
                      gen_statem:state_enter_result(term());
                  (gen_statem:event_type(),
                   Msg :: term(),
                   State :: term(),
                   Data :: term()) ->
                      gen_statem:event_handler_result(term()).

%% The handle_event functions are organized in order of calls -> [casts ->]
%% timeouts -> info

%% Connect state change from open to version_neg.
handle_event({call, From}, {connect, Address, Port, Timeout}, 
             open, #quic_conn{opts=Opts}=Conn0) ->

  {ok, LSocket} = quic_prim:open(Opts),

  %% Try and connect to server
  case quic_prim:connect(Conn0#quic_conn{socket=LSocket, 
                                         ip_addr=Address, 
                                         port=Port}, Timeout) of
    {ok, Conn} ->
      %% successful connection. Enter connected state and reply with socket.
      {next_state, connected, {Conn, #quic_packet{}, {[], []}}, 
       [{reply, From, {ok, LSocket}}]};

    Error ->
      %% unsuccessful connection. Close the statem.
      {stop, Error, Conn0}
  end;

handle_event({call, From}, {listen, Port}, 
             open, #quic_conn{opts=Opts} = Conn0) ->

  case quic_prim:open(Port, Opts) of
    {ok, LSocket} ->
      %% successful opening of listening socket
      {next_state, listen, 
       Conn0#quic_conn{socket=LSocket},
       [{reply, From, {ok, LSocket}}]};

    Error ->
      %% failure to open port
      {stop, Error, Conn0}
  end;

handle_event({call, From}, 
             {accept, Timeout},
             listen,
             #quic_conn{socket=LSocket}=Conn0) ->

  ?DBG("Waiting to receive packet on socket: ~p~n", [Socket])
    case quic_prim:recvfrom(LSocket, Timeout) of
      {ok, {Address, Port, Packet}} ->
        ?DBG("Packet received from ~p:~p~n", [Address, Port]),
        ?DBG("Parsing Packet: ~p~n", [Packet]),
        
        case quic_packet:parse_packet(#quic_conn{}, Packet) of
          {ok, {new, Conn}} ->
            %% Received new connection request
            %% Start new statem for connection
            case new_conn(Conn) of
              {ok, {Client_Socket, Pid}} ->
                %% Loop back to listen state and wait for other accept call.
                %% reply with new connection socket and statem pid.
                {keep_state_and_data,
                 [{reply, From, {ok, {new, Client_Socket, Pid}}}]};
              Connect_Error ->
                ?DBG("Error connecting with client after request: ~p~n", [Conn]),
                {keep_state_and_data,
                 [{reply, From, Connect_Error}]}
            end;

          {ok, {existing, Conn}} ->
            %% Received reconnection request
            ?DBG("Reconnect not implemented yet~n", []),
            {keep_state_and_data,
             [{reply, From, {ok, {existing, Conn#quic_conn.socket}}}]};

          Parse_Error ->
            ?DBG("Error parsing packet: ~p~n", [Parse_Error]),
            {keep_state_and_data, 
             [{reply, From, Parse_Error}]}
        end;

      Receive_Error->
        {stop, Receive_Error, Conn0}
    end;

handle_event({call, From}, {send, Data}, connected, 
             {Conn, #quic_packet{}, Recv}) ->
  %% Formats the Data received into the appropriate packet and frame.
  %% The packet may not be immediately sent due to pacing and congestion
  %% control as sending small amounts of information in individual packets
  %% is inefficient. Sets up a timer to force a send.
  ?DBG("Creating packet and starting send timer~n", []),

  {ok, Packet} = quic_packet:form_packet(Conn, Data),

  {keep_state, {Conn, Packet, Recv}, [{reply, From, ok}, 
                                      {{timeout, send}, quic_recovery:pacing(), send}]};

handle_event({call, From}, {send, Data}, connected, 
             {Conn, Quic_Packet, Recv}) ->
  %% Formats the Data received into the appropriate packet and frame.
  %% The packet is not immediately sent.
  %% need clause to send when Packet is larger than send window.
  ?DBG("More data added to packet~n", []),

  {ok, Packet} = quic_packet:form_packet(Conn, Quic_Packet, Data),

  {keep_state, {Conn, Packet, Recv}, [{reply, From, ok}]};

handle_event({call, From}, {recv, _Timeout}, 
             {_Conn, _Packet, {active, _Owner}}=Data) ->
  ?DBG("Tried calling recv when socket is active~n", []),
  {keep_state_and_data, [{reply, From, {error, einval}}]};

handle_event({call, From}, {recv, Timeout}, 
             {#quic_conn{socket=Socket, ip_addr=IP, port=Port}=Conn, 
              _New_Packet, {[], []}}=Data) ->
  ?DBG("No packets to receive. Waiting to receive one.~n", []),
  receive
    {udp, Socket, IP, Port, Packet} ->
      {ok, Parsed_Packet} = quic_packet:parse_packet(Conn, Packet),
      {keep_state_and_data, [{reply, From, Parsed_Packet}]};
  after 
    Timeout ->
      {keep_state_and_data, [{reply, From, {error, timeout}}]}
  end;

handle_event({call, From}, {recv, _Timeout}, 
             {Conn, Data, {[Next | Rest], Reversed}}) ->
  ?DBG("Sending first received packet.~n", []),
  {keep_state, {Conn, Data, {Rest, Reversed}}, [{reply, From, Next}]};

handle_event({call, From}, {recv, _Timeout}, 
             {Conn, New_Packet, {[], Reversed}}) ->
  ?DBG("Reversing packets and sending next.~n", []),
  [Next | Packets] = lists:reverse(Reversed),
  {keep_state, {Conn, Data, {Packets, []}}, [{reply, From, {ok, Next}}]};

handle_event({call, From}, close, connected, {Conn, Packet, Recv}) ->
  %% send packet and flush recv. Wait for acks.

  {next_state, closing, {Conn, #quic_packet{}, Recv}, 
   [{{timeout, recover}, quic_recovery:timeout(), {recover, Packet}}, 
    {reply, From, ok}]};

handle_event({call,From}, _Msg, State, Data) ->
  {next_state, State, Data, [{reply,From,ok}]};

%%
%% The following are all of the timeouts for the statem.
%%

handle_event({timeout, recover}, {recover, Packet}, closing, 
             {Conn, _, Recv}) ->
  %% resend packet and wait for acks.
  ?DBG("resending packet before closing~n", []),
  {keep_state_and_data, 
   [{{timeout, recover}, quic_recovery:timeout(), {recover, Packet}}]};

handle_event({timeout, send}, send, connected, {Conn, Packet}) ->
  %% This is the forced send timeout event. A new timer is started to handle
  %% the recovery of a lost packet and the Data Packet is reset to empty.
  ?DBG("Timeout, sending packet~n", []),  

  {keep_state, {Conn, []}, 
   [{{timeout, recover}, quic_recovery:timeout(), {recover, Packet}}]};

handle_event({timeout, recover}, {recover, Packet}, connected, 
             {Conn, New_Packet, Recv}) ->
  %% Timeout for receiving acks of a sent packet. Packet assumed lost.
  %% Resend packet and reset timer and congestion control info.
  %% TODO: reprocess frames in Packet to add New_Packet info.
  ?DBG("Recovery timeout received. Resending packet~n", []),

  {keep_state, {Conn, New_Packet, Recv},
   [{{timeout, recover}, quic_recovery:timeout(), {recover, Packet}}]};

%%
%% The following are the info events (active udp message receives)
%% 

handle_event(info, {udp, Socket, IP, Port, Recv_Packet}, connected,
             {#quic_conn{socket=Socket, ip_addr=IP, port=Port}=Conn, 
              New_Packet, {active, Owner}}) ->
  ?DBG("Received packet from ~p:~p~n", [IP, Port]),
  %% Parse the received packet.
  {ok, Parsed_Packet} = quic_packet:parse_packet(Conn, Recv_Packet),
  %% Build acks for the received packet
  {ok, Ack_Frame} = quic_packet:form_acks(Conn, Parsed_Packet),
  %% Add acks to next packet to send.
  {ok, Packet} = quic_packet:form_packet(Conn, New_Packet, Parsed_Packet),
  %% Relay received packet to owner process
  Owner ! {quic, Socket, Parsed_Packet},
  ?DBG("Packet Parsed, Acked, and Sent.~n", []),

  %% Maybe set another timeout for packets with ack frames in them?
  {keep_state, {Conn, Packet, {active, Owner}}};


handle_event(info, {udp, Socket, IP, Port, Recv_Packet}, connected,
             {#quic_conn{socket=Socket, ip_addr=IP, port=Port}=Conn, 
              New_Packet, {{active, N}, Owner}}) ->
  ?DBG("Received packet from ~p:~p~n", [IP, Port]),
  %% Parse the received packet.
  {ok, Parsed_Packet} = quic_packet:parse_packet(Conn, Recv_Packet),
  %% Build acks for the received packet
  {ok, Ack_Frame} = quic_packet:form_acks(Parsed_Packet),
  %% Add acks to next packet to send.
  {ok, Packet} = quic_packet:form_packet(Conn, New_Packet, Parsed_Packet),
  %% Relay received packet to owner process
  Owner ! {quic, Socket, Parsed_Packet},

  ?DBG("Packet Parsed, Acked, and Sent.~n", []),

  if
    N > 1 ->
      {keep_state, {Conn, Packet, {{active, N-1}, Owner}}};
    true ->
      Owner ! {quic_passive, Socket},
      {keep_state, {Conn, Packet, {[], []}}}
  end;

handle_event(info, {udp, Socket, IP, Port, Recv_Packet}, connected,
             {#quic_conn{socket=Socket, ip_addr=IP, port=Port}=Conn,
              Send_Packet, {Ordered, Reversed}}) ->
  ?DBG("Received packet from ~p:~p~n", [IP, Port]),
  %% Parse the received packet
  {ok, Parsed_Packet} = quic_packet:parse_packet(Conn, Recv_Packet),
  %% Form acks to send back
  {ok, Ack_Frame} = quic_packet:form_acks(Parsed_Packet),
  %% Add acks to next packet to send
  {ok, New_Packet} = 
    quic_packet:form_packet(Conn, Send_Packet, Parsed_Packet),
  %% Add parsed packet to reversed list and change to 
  ?DBG("Packet Parsed and Acked. Queuing it up~n", []),
  {keep_state, {Conn, New_Packet, {Ordered, [Parsed_Packet | Reversed]}}}.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_statem when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_statem terminates with
%% Reason. The return value is ignored.
%% @end
%%--------------------------------------------------------------------
-spec terminate(Reason :: term(), State :: term(), Data :: term()) ->
                   any().
terminate(_Reason, _State, _Data) ->
  void.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%% @end
%%--------------------------------------------------------------------
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

%% Simple functions to just cut down on wordage.
call(Pid, Msg) ->
  gen_statem:call(Pid, Msg).

cast(Pid, Msg) ->
  gen_statem:cast(Pid, Msg).


new_conn(#quic_conn{opts=Opts}=Conn) ->
  %% Open a new socket.
  ?DBG("Opening new socket for client connection~n", []),

  case quic_prim:open(Opts) of
    {ok, Socket} ->
      %% Start gen_statem process, state connected.
      ?DBG("Starting statem in connected state.~n", []),
      {ok, Pid} = start_link(Conn#quic_conn{socket=Socket}),
      quic_prim:controlling_process(Socket, Pid),
      {ok, {Socket, Pid}};
    Error ->
      Error
  end.


