%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%%
%%% @end
%%% Created : 23 May 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_db).

%% API
-export([init/0]).
-export([add_conn/2, update_pid/2, delete/1, lookup/1]).

-define(TABLE, ?MODULE).

-include("quic_headers.hrl").

%%%===================================================================
%%% API
%%%===================================================================

init() ->
  try ets:new(?TABLE, [named_table, public, set, {read_concurrency, true}]) of
      _ -> ?TABLE
  catch
    error:badarg ->
      ?DBG("quic_db table already exists.~n", []),
      ?TABLE
  end.
      

add_conn(Socket, Pid) when is_port(Socket), is_pid(PID) ->
  ets:insert_new(?TABLE, {Socket, Pid}).


update_pid(Socket, New_Pid) when is_port(Socket), is_pid(New_Pid) ->
  ets:insert(?TABLE, {Socket, Pid}).


delete(Socket) when is_port(Socket) ->
  ets:delete(?TABLE, Socket).


lookup(Socket) when is_port(Socket) ->
  case ets:lookup(?TABLE, Socket) of
    [] ->
      {error, eexist};
    [Pid] ->
      {ok, Pid};
    Error ->
      ?DBG("This should not happen when looking up. ~p~n", [Error]),
      Error
  end.


%%%===================================================================
%%% Internal functions
%%%===================================================================
