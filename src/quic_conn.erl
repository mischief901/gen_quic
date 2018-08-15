%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%% The quic_conn module creates a new quic connection and
%%% allows for multiplexing/demultiplexing across the connection
%%% by creating streams. See the quic_stream module for details 
%%% on individual stream processes.
%%% quic_conn has the apis for the quic_server and quic_client state machines
%%% accept spawns a gen_statem with quic_server as the callback module and 
%%% connect spawns a gen_statem with quic_client as the callback module.
%%% Both quic_server and quic_client import common functions from this module.
%%% @end
%%% Created : 29 Jun 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_conn).

-export([connect/4]).
-export([listen/2]).
-export([accept/3]).
-export([open/2]).
-export([send/2]).
-export([recv/3]).
-export([controlling_process/2]).
-export([close/1]).

%% Internal shared function for quic_client and quic_server
-export([handle_frame/2]).
-export([send_and_form_packet/2]).

-include("quic_headers.hrl").


%%%===================================================================
%%% API
%%%===================================================================

-spec connect(Address, Port, Opts, Timeout) -> Result when
    Address :: inet:address(),
    Port :: inet:port_number(),
    Opts :: [Opt],
    Opt :: gen_quic:option(),
    Timeout :: non_neg_integer(),
    Result :: {ok, Socket} | {error, Reason},
    Socket :: inet:socket(),
    Reason :: inet:posix().

connect(Address, Port, Opts, Timeout) ->
  {ok, Quic_Opts} = inet_quic_util:parse_opts(Opts),

  %% This socket should remain active regardless of the options.
  {ok, Socket} = inet_udp:open([{active, true} | Opts]),
  
  Data = #quic_data{
            type = client,
            conn = #quic_conn{
                      socket = Socket,
                      owner = self()
                     }
           },

  {ok, Pid} = gen_statem:start_link(via(Socket), quic_client,
                                    [Data, Quic_Opts], []),
  
  inet_udp:controlling_process(Socket, Pid),
  
  gen_statem:call(Pid, {connect, Address, Port, Timeout}).


-spec listen(Port, Opts) -> Result when
    Port :: inet:port_number(),
    Opts :: [Opt],
    Opt :: gen_quic:option(),
    Result :: {ok, Socket} | {error, Reason},
    Socket :: gen_quic:socket(),
    Reason :: inet:posix().

listen(Port, Opts) ->
  inet_udp:open(Port, Opts).


-spec accept(LSocket, Timeout, Options) -> Result when
    LSocket :: gen_quic:socket(),
    Timeout :: non_neg_integer(),
    Options :: [Option],
    Option :: gen_quic:options(),
    Result :: {ok, Socket} | {error, Reason},
    Socket :: gen_quic:socket(),
    Reason :: inet:posix() | timeout.

accept(LSocket, Timeout, Opts) ->
  
  {ok, Quic_Opts} = inet_quic_util:parse_opts(Opts),

  %% This socket should remain active regardless of the options.
  {ok, Socket} = inet_udp:open([{active, true} | Opts]),
  
  
  Data = #quic_data{
            type = server,
            conn = #quic_conn{
                      socket = Socket,
                      owner = self()
                     }
           },

  {ok, Pid} = gen_statem:start_link(via(Socket), quic_server,
                                    [Data, Quic_Opts], []),
  
  inet_udp:controlling_process(Socket, Pid),
  
  gen_statem:call(Pid, {accept, LSocket, Timeout}).

%% TODO: update for new quic_client/quic_server modules.
%% Should probably be the start_link or start for the quic_stream gen_server.
%% Opens a new stream on the given Socket.
-spec open(Socket, Opts) -> Result when
    Socket :: gen_quic:socket(),
    Opts :: [Opt],
    Opt :: gen_quic:socket_option(),
    Result :: {ok, Stream} | {error, Reason},
    Stream :: {Socket, Stream_ID},
    Stream_ID :: non_neg_integer(),
    Reason :: gen_quic:errors().

open(Socket, Opts) ->
  %% Something like this. The gen_statem opens the quic_stream gen_server so it
  %% can trap and manage exits and open streams when receiving an open stream frame
  case gen_statem:call(via(Socket), {open_stream, Opts}) of
    {ok, Stream_ID} ->
      {ok, {Socket, Stream_ID}};
    
    {error, Reason} ->
      {error, Reason}
  end.

-spec send(Socket, Message) -> ok when
    Socket :: gen_quic:socket(),
    Message :: binary().

send(Socket, Message) when is_tuple(Socket) ->
  %% For streams.
  gen_server:cast(Socket, {send, Message});

send(Socket, Message) ->
  gen_statem:cast(via(Socket), {send, Message}).

%% Packet Length is ignored since it is a datagram.
-spec recv(Socket, Length, Timeout) -> Result when
    Socket :: gen_quic:socket(),
    Length :: non_neg_integer(),
    Timeout :: non_neg_integer() | infinity,
    Result :: {ok, Data} | {error, Reason},
    Data :: list() | binary(),
    Reason :: inet:posix() | timeout.

recv(Socket, _Length, Timeout) when is_tuple(Socket) ->
  %% For streams.
  gen_server:call(via(Socket), recv, Timeout);

recv(Socket, _Length, Timeout) ->
  gen_statem:call(via(Socket), recv, Timeout).


-spec controlling_process(Socket, Pid) -> Result when
    Socket :: gen_quic:socket(),
    Pid :: pid(),
    Result :: ok | {error, Reason},
    Reason :: closed | not_owner | badarg | inet:posix().

controlling_process(Socket, Pid) when is_tuple(Socket) ->
  gen_server:call(via(Socket), {controlling_process, Pid});

controlling_process(Socket, Pid) ->
  gen_statem:call(via(Socket), {controlling_process, Pid}).


-spec close(Socket) -> ok when
    Socket :: gen_quic:socket().

close(Socket) when is_tuple(Socket) ->
  gen_server:cast(via(Socket), close);

close(Socket) ->
  gen_statem:cast(via(Socket), close).



via(Socket) ->
  {via, quic_registry, Socket}.


%% This function should behave the exact same across both quic_server and quic_client.
-spec handle_frame(Frame, Data) -> Data when
    Data :: #quic_data{},
    Frame :: quic_frame().

handle_frame(#{
               type := stream_data,
               stream_id := Stream_ID
              } = Frame,
             #quic_data{
                conn = #quic_conn{
                          socket = Socket
                         }
               } = Data) ->
  %% Cast the Stream Frame to the Stream gen_server denoted by {Socket, Stream_ID}.
  gen_server:cast(via({Socket, Stream_ID}), {recv, Frame}),
  Data;

handle_frame(#{
               type := stream_open,
               stream_id := Stream_ID,
               stream_type := Type
              } = Frame,
             #quic_data{
                conn = #quic_conn{
                          socket = Socket,
                          owner = Owner
                         }
               } = Data) ->
  %% Spawn a new quic_stream gen_server and send a message to the owner.
  %% TODO: Add checks to see if a stream can be opened or if limit has been reached.
  %% TODO: Move to having a supervisor:spawn_child system.
  {ok, _Pid} = gen_server:start(via({Socket, Stream_ID}), quic_stream, 
                                [Owner, Socket, Frame], []),

  Owner ! {stream_open, {Socket, Stream_ID}, Type},
  Data;

handle_frame(#{} = Frame, #quic_data{} = Data) ->

  Data.
    

send_and_form_packet(Pkt_Type,
                     #quic_data{
                        window_timeout = undefined
                        } = Data) ->
  %% Timeout window is not set yet. Set it to the default 100 milliseconds.
  %% "If no previous RTT is available, or if the network changes, the 
  %%  initial RTT SHOULD be set to 100ms."
  %% from QUIC Recovery
  send_and_form_packet(Pkt_Type, 
                       Data#quic_data{
                         window_timeout = #{rto => 100}
                        });

send_and_form_packet({short, Frames} = Pkt_Type,
                     #quic_data{
                        window_timeout = #{rto := Timeout} = Win,
                        app_pkt_num = Pkt_Num
                       } = Data0) ->

  {ok, #quic_data{
          conn = #quic_conn{
                    socket = Socket,
                    address = IP,
                    port = Port}
         } = Data1, Packet} = quic_crypto:form_packet(short, Data0, Frames),
  
  ok = prim_inet:sendto(Socket, IP, Port, Packet),

  %% We want to set a re-send timer to resend the packet if no ack
  %% has been received yet.
  Timer_Ref = erlang:start_timer(Timeout, self(), {Pkt_Type, Pkt_Num, Timeout}),
  %% And update the window_timeout map to include it as well.
  %% This allows us to cancel the timer when an Ack is received.
  Data1#quic_data{window_timeout = Win#{Timer_Ref => {Pkt_Type, Pkt_Num, Timeout}}};

send_and_form_packet({ealry_data, Frames} = Pkt_Type,
                     #quic_data{
                        window_timeout = #{rto := Timeout} = Win,
                        init_pkt_num = Pkt_Num
                       } = Data0) ->

  {ok, #quic_data{
          conn = #quic_conn{
                    socket = Socket,
                    address = IP,
                    port = Port}
         } = Data1, 
   Packet} = quic_crypto:form_packet(early_data, Data0, Frames),
  
  ok = prim_inet:sendto(Socket, IP, Port, Packet),

  %% We want to set a re-send timer to resend the packet if no ack
  %% has been received yet.
  Timer_Ref = erlang:start_timer(Timeout, self(), {Pkt_Type, Pkt_Num, Timeout}),
  %% And update the window_timeout map to include it as well.
  %% This allows us to cancel the timer when an Ack is received.
  Data1#quic_data{window_timeout = Win#{Timer_Ref => {Pkt_Type, Pkt_Num, Timeout}}};

send_and_form_packet(Pkt_Type, 
                     #quic_data{
                        window_timeout = #{rto := Timeout} = Win,
                        init_pkt_num = IPN,
                        hand_pkt_num = HPN
                       } = Data0) ->
  %% Forms the packet and sends it.
  %% Mostly just a wrapper function around these two functions.
  {ok, #quic_data{
          conn = #quic_conn{
                    socket = Socket,
                    address = IP,
                    port = Port}
         } = Data1, Packet} = quic_crypto:form_packet(Pkt_Type, Data0),
  
  ok = prim_inet:sendto(Socket, IP, Port, Packet),

  Pkt_Num = 
    case Pkt_Type of
      initial -> IPN;
      _Other -> HPN
    end,

  %% We want to set a re-send timer to resend the packet if no ack
  %% has been received yet.
  Timer_Ref = erlang:start_timer(Timeout, self(), {Pkt_Type, Pkt_Num, Timeout}),
  %% And update the window_timeout map to include it as well.
  %% This allows us to cancel the timer when an Ack is received.
  Data1#quic_data{window_timeout = Win#{Timer_Ref => {Pkt_Type, Pkt_Num, Timeout}}}.

