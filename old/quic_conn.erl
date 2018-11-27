%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%%
%%% @end
%%% Created : 26 Jun 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_conn).

-behaviour(gen_server).

-export([connect/4]).
-export([listen/2]).
-export([accept/2]).
-export([open/2]).
-export([send/2]).
-export([recv/3]).
-export([close/1]).

%% API
-export([start_link/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3, format_status/2]).

-include("quic_headers.hrl").

%%%===================================================================
%%% API
%%%===================================================================

-spec connect(Address, Port, Opts, Timeout) -> 
                 {ok, Socket} | {error, Posix} when
    Address :: inet:socket_address(),
    Port :: inet:port_number(),
    Opts :: [Opt],
    Opt :: gen_quic:option(),
    Timeout :: non_neg_integer(),
    Socket :: gen_quic:socket(),
    Posix :: inet:posix().

connect(Address, Port, Opts, Timeout) ->
  ?DBG("Trying to connect to ~p on ~p~n", [Address, Port]),
  
  {ok, Socket} = quic_prim:connect(Opts),
  ?DBG("Socket opened.~n", []),
  
  {ok, Pid} = start_link(Socket),
  ok = quic_prim:controlling_process(Socket, Pid),
  ?DBG("StateM started.~n", []),
  
  gen_statem:call(via(Socket), {connect, Address, Port, Timeout}).


-spec listen(Port, Opts) -> {ok, Socket} | {error, Posix} when
    Port :: inet:port_number(),
    Opts :: [Opt],
    Opt :: gen_quic:option(),
    Socket :: gen_quic:socket(),
    Posix :: inet:posix().

listen(Port, Opts) ->
  case inet_quic_util:is_opt(Opts, buffer_accept) of
    true ->
      ?DBG("Calling quic_server:listen"),
      quic_server:listen(Port, Opts);

    false ->
      ?DBG("Listening on port: ~p~n", [Port]),
      
      {ok, Socket} = quic_prim:open(Port, Opts),
      ?DBG("Socket opened~n", []),

      ok = quic_prim:controlling_socket(Socket, Pid),
      ?DBG("StateM started~n", []),

      {ok, Socket}
  end.


-spec accept(LSocket, Timeout) -> Result when
    LSocket :: gen_quic:socket(),
    Timeout :: non_neg_integer(),
    Result :: {ok, Socket} | {error, Reason},
    Socket :: gen_quic:socket(),
    Reason :: inet:posix() | timeout.

%% Check to see if the socket is a registered gen_server by the buffer_accept option.
%% If yes it checks the gen_server, otherwise it bypasses it and waits for a request.
accept(LSocket, Timeout) ->
  case quic_registry:whereis_name(LSocket) of
    undefined ->
      quic_server:immediate_accept(LSocket, Timeout);

    Pid when is_pid(Pid) ->
      quic_server:accept(Lsocket, Timeout)
  end.


%% Opens a new stream on the given Socket.
-spec open(Socket, Opts) -> Result when
    Socket :: gen_quic:socket(),
    Opts :: [Opt],
    Opt :: gen_quic:socket_option(),
    Result :: {ok, StreamID} | {error, Reason},
    StreamID :: {Socket, non_neg_integer()},
    Reason :: gen_quic:error().

open(Socket, Opts) ->
  quic_stream:open(Socket, Opts).


-spec send(Socket, Message) -> ok when
    Socket :: port(),
    Message :: list().

send(Socket, Message) when is_list(Message) ->
  gen_statem:cast(via(Socket), {send, Message});

send(Socket, Message) ->
  {error, einval}.


-spec recv(Socket, Length, Timeout) -> Result when
    Socket :: port(),
    Length :: integer(),
    Timeout :: non_neg_integer(),
    Result {ok, Data} | {error, Reason},
    Data :: list(),
    Reason :: inet:posix() | timeout.

recv(Socket, _Length, Timeout) ->
  gen_statem:call(via(Socket), {send, Message}).


-spec close(Socket) -> ok when
    Socket :: port() | {Socket, Stream_ID},
    Stream_ID :: non_neg_integer().

close({Socket, Stream}) ->
  gen_statem:cast(via(Socket), {stop_stream, Stream});

close(Socket) ->
  gen_statem:stop(via(Socket), {stop, Socket}, infinity).


-spec close(Socket, Timeout) -> ok when
    Socket :: port(),
    Timeout :: non_neg_integer().

close(Socket, Timeout) ->
  gen_statem:stop(via(Socket), {stop, Socket}, Timeout).


-spec start_link(Socket) ->
                    {ok, Pid :: pid()} |
                    ignore |
                    {error, Error :: term()}.
                   
start_link(Socket) ->
  gen_statem:start_link(via(Socket), ?MODULE, [], []).

%%%===================================================================
%%% gen_statem callbacks
%%%===================================================================

-spec callback_mode() -> gen_statem:callback_mode_result().

callback_mode() -> state_functions.


-spec init(Args :: term()) ->
              gen_statem:init_result(atom()).

init([]) ->
  process_flag(trap_exit, true),
  {ok, state_name, #data{}}.


-spec state_name('enter',
                 OldState :: atom(),
                 Data :: term()) ->
                    gen_statem:state_enter_result('state_name');
                (gen_statem:event_type(),
                 Msg :: term(),
                 Data :: term()) ->
                    gen_statem:event_handler_result(atom()).

state_name({call,Caller}, _Msg, Data) ->
  {next_state, state_name, Data, [{reply,Caller,ok}]}.



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


%% A simple function wrapper for the name of the gen_state.
%% Returns {via, quic_registry, Socket}.

-spec via(Socket) -> {via, atom(), Socket} when
    Socket :: inet:socket_address().

via(Socket) ->
  {via, quic_registry, Socket}.
