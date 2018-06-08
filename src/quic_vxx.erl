%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%%
%%% @end
%%% Created :  1 Jun 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_vxx).

-behaviour(gen_server).

%% API
%% MAYBE: Move to new file for parsing utility functions?
-export([parse_var_length/1, to_var_length/1]).

-export([supported/1]).
-export([start_link/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3, format_status/2]).

-define(SERVER, ?MODULE).

-include("quic_headers.hrl").
-include("quic_vx_1.hrl").

-record(state, {supported}).

%%%===================================================================
%%% API
%%%===================================================================

%% Common functions for all versions.

%% Reads a variable length integer from the given Binary.
parse_var_length(<<0:1, 0:1, Integer:6, Rest/binary>>) ->
  {Integer, Rest};
parse_var_length(<<0:1, 1:1, Integer:14, Rest/binary>>) ->
  {Integer, Rest};
parse_var_length(<<1:1, 0:1, Integer:30, Rest/binary>>) ->
  {Integer, Rest};
parse_var_length(<<1:1, 1:1, Integer:62, Rest/binary>>) ->
  {Integer, Rest};
parse_var_length(Other) ->
  ?DBG("Incorrect variable length encoded integer: ~p~n", [Other]),
  {error, badarg}.

%% Creates the smallest possible variable length integer.
to_var_length(Integer) when Integer < 64 ->
  list_to_bitstring([<<0:2>>, <<Integer:6>>]);

to_var_length(Integer) when Integer < 16384 ->
  list_to_bitstring([<<1:2>>, <<Integer:14>>]);

to_var_length(Integer) when Integer < 1073741824 ->
  list_to_bitstring([<<2:2>>, <<Integer:30>>]);

to_var_length(Integer) ->
  list_to_bitstring([<<3:2>>, <<Integer:62>>]).



-spec supported(Version) -> {ok, {Module, Version}} |
                            {error, Error} when
    Version :: binary(),
    Module :: atom(),
    Error :: term().

supported(Version) ->
  gen_server:call(?SERVER, {check, Version}).

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%% @end
%%--------------------------------------------------------------------
-spec start_link(Versions) -> {ok, Pid :: pid()} |
                      {error, Error :: {already_started, pid()}} |
                      {error, Error :: term()} |
                      ignore when
    Versions :: [{Module, Version}],
    Module :: atom(),
    Version :: binary().

start_link(Versions) ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [Versions], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%% @end
%%--------------------------------------------------------------------
-spec init(Args :: term()) -> {ok, State :: term()} |
                              {ok, State :: term(), Timeout :: timeout()} |
                              {ok, State :: term(), hibernate} |
                              {stop, Reason :: term()} |
                              ignore.

init([Versions]) ->
  process_flag(trap_exit, false),
  Default = {quic_vx_1, <<?VERSION_NUMBER:32>>},
  {ok, #state{supported=[Default | Versions]}}.
  

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%% @end
%%--------------------------------------------------------------------
-spec handle_call(Request :: term(), From :: {pid(), term()}, State :: term()) ->
                     {reply, Reply :: term(), NewState :: term()} |
                     {reply, Reply :: term(), NewState :: term(), Timeout :: timeout()} |
                     {reply, Reply :: term(), NewState :: term(), hibernate} |
                     {noreply, NewState :: term()} |
                     {noreply, NewState :: term(), Timeout :: timeout()} |
                     {noreply, NewState :: term(), hibernate} |
                     {stop, Reason :: term(), Reply :: term(), NewState :: term()} |
                     {stop, Reason :: term(), NewState :: term()}.

handle_call({check, Version}, _From, 
            #state{supported=Supported}=State) ->
  case lists:keyfind(Version, 2, Supported) of
    false ->
      ?DBG("Version ~p not found.~n", [Version]),
      {reply, {error, unsupported}, State};
    {_Module, Version} = Support ->
      ?DBG("Version ~p Supported.~n", [Version]),
      {reply, {ok, Support}, State};
    Other ->
      ?DBG("Error checking version with lists:keyfind: ~p~n", [Other]),
      {reply, Other, State}
  end;

handle_call(_Request, _From, State) ->
  Reply = ok,
  {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%% @end
%%--------------------------------------------------------------------
-spec handle_cast(Request :: term(), State :: term()) ->
                     {noreply, NewState :: term()} |
                     {noreply, NewState :: term(), Timeout :: timeout()} |
                     {noreply, NewState :: term(), hibernate} |
                     {stop, Reason :: term(), NewState :: term()}.
handle_cast(_Request, State) ->
  {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%% @end
%%--------------------------------------------------------------------
-spec handle_info(Info :: timeout() | term(), State :: term()) ->
                     {noreply, NewState :: term()} |
                     {noreply, NewState :: term(), Timeout :: timeout()} |
                     {noreply, NewState :: term(), hibernate} |
                     {stop, Reason :: normal | term(), NewState :: term()}.
handle_info(_Info, State) ->
  {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%% @end
%%--------------------------------------------------------------------
-spec terminate(Reason :: normal | shutdown | {shutdown, term()} | term(),
                State :: term()) -> any().
terminate(_Reason, _State) ->
  ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%% @end
%%--------------------------------------------------------------------
-spec code_change(OldVsn :: term() | {down, term()},
                  State :: term(),
                  Extra :: term()) -> {ok, NewState :: term()} |
                                      {error, Reason :: term()}.
code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called for changing the form and appearance
%% of gen_server status when it is returned from sys:get_status/1,2
%% or when it appears in termination error logs.
%% @end
%%--------------------------------------------------------------------
-spec format_status(Opt :: normal | terminate,
                    Status :: list()) -> Status :: term().
format_status(_Opt, Status) ->
  Status.

%%%===================================================================
%%% Internal functions
%%%===================================================================
