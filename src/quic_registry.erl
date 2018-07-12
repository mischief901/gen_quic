%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%% This is the register for keeping track of each separate socket.
%%% These functions are called by start_link using {via, quic_registry, name}.
%%% Eventually, this will be moved to an ETS table or another data
%%% structure for better performance.
%%% @end
%%% Created : 26 Jun 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_registry).

-behaviour(gen_server).

-export([register_name/2, unregister_name/1]).
-export([whereis_name/1]).
-export([send/2]).

%% API
-export([start_link/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3, format_status/2]).

-define(SERVER, ?MODULE).

-record(conns, {conn}).

%%%===================================================================
%%% API
%%%===================================================================

-spec register_name(Name, Pid) -> yes | no when
    Name :: term(),
    Pid :: pid().

register_name(Name, Pid) ->
  gen_server:call(?SERVER, {add, {Name, Pid}}).


-spec unregister_name(Name) -> ok when
    Name :: term().

unregister_name(Name) ->
  gen_server:cast(?SERVER, {remove, Name}).


-spec whereis_name(Name) -> Result when
    Name :: term(),
    Result :: Pid | undefined.

whereis_name(Name) ->
  gen_server:call(?SERVER, {whereis, Name}).

-spec send(Name, Message) -> Result when
    Name :: term(),
    Message :: term(),
    Result :: ok.

send(Name, Msg) ->
  case whereis_name(Name) of
    Pid when is_pid(Pid) ->
      Pid ! Msg,
      ok;

    undefined ->
      exit({badarg, {Name, Msg}})
  end.


-spec start_link() -> {ok, Pid :: pid()} |
                      {error, Error :: {already_started, pid()}} |
                      {error, Error :: term()} |
                      ignore.
start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

-spec init(Args :: term()) -> {ok, State :: term()} |
                              {ok, State :: term(), Timeout :: timeout()} |
                              {ok, State :: term(), hibernate} |
                              {stop, Reason :: term()} |
                              ignore.

init([]) ->
  process_flag(trap_exit, true),
  {ok, #conns{conn=[]}}.


-spec handle_call(Request :: term(), From :: {pid(), term()}, State :: term()) ->
                     {reply, Reply :: term(), NewState :: term()} |
                     {reply, Reply :: term(), NewState :: term(), Timeout :: timeout()} |
                     {reply, Reply :: term(), NewState :: term(), hibernate} |
                     {noreply, NewState :: term()} |
                     {noreply, NewState :: term(), Timeout :: timeout()} |
                     {noreply, NewState :: term(), hibernate} |
                     {stop, Reason :: term(), Reply :: term(), NewState :: term()} |
                     {stop, Reason :: term(), NewState :: term()}.

handle_call({add, {Name, Pid}}, _From, #conns{conn=Conns}=State) ->
  case lists:keyfind(Name, 1, Conns) of
    false ->
      {reply, yes, #conns{[{Name, Pid} | Conns]}};
    Other ->
      {reply, no, State}
  end;

handle_call({whereis, Name}, _From, #conns{conn=Conns}=State) ->
  case lists:keyfind(Name, 1, Conns) of
    {Name, Pid} when is_pid(Pid) ->
      {reply, Pid, State};
    false ->
      {reply, undefined, State}
  end.


-spec handle_cast(Request :: term(), State :: term()) ->
                     {noreply, NewState :: term()} |
                     {noreply, NewState :: term(), Timeout :: timeout()} |
                     {noreply, NewState :: term(), hibernate} |
                     {stop, Reason :: term(), NewState :: term()}.

handle_cast({remove, Name}, #conns{conn=Conn}) ->
  New_State = lists:keydelete(Name, 1, Conn),
  {noreply, New_State}.



-spec handle_info(Info :: timeout() | term(), State :: term()) ->
                     {noreply, NewState :: term()} |
                     {noreply, NewState :: term(), Timeout :: timeout()} |
                     {noreply, NewState :: term(), hibernate} |
                     {stop, Reason :: normal | term(), NewState :: term()}.

handle_info(Info, State) ->
  io:format("Message received by quic_registry: ~p~n", [Info]),
  {noreply, State}.


-spec terminate(Reason :: normal | shutdown | {shutdown, term()} | term(),
                State :: term()) -> any().

terminate(_Reason, _State) ->
  ok.


-spec code_change(OldVsn :: term() | {down, term()},
                  State :: term(),
                  Extra :: term()) -> {ok, NewState :: term()} |
                                      {error, Reason :: term()}.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.


-spec format_status(Opt :: normal | terminate,
                    Status :: list()) -> Status :: term().

format_status(_Opt, Status) ->
  Status.

%%%===================================================================
%%% Internal functions
%%%===================================================================
