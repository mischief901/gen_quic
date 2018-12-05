%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%% This is the register for keeping track of each separate socket.
%%% These functions are called by start_link using {via, quic_registry, Socket}.
%%% This will need to be wrapped into a gen_server so that all the lookups and 
%%% mutations are kept atomic.
%%% @end
%%%-------------------------------------------------------------------
-module(quic_registry).

-export([start/0]).
-export([register_name/2, unregister_name/1]).
-export([register_stream/2, unregister_stream/1]).
-export([register_conn_id/2, unregister_conn_id/1]).
-export([whereis_name/1]).
-export([whereis_conn_id/1]).
-export([send/2]).


-define(TABLE, quic_registry).
-define(CONN_TABLE, quic_conn_table).

%%%===================================================================
%%% API
%%%===================================================================

-spec start() -> ok.

start() ->
  ets:new(?TABLE, [named_table, public, set]),
  ets:new(?CONN_TABLE, [named_table, public, set]),
  ok.


-spec register_name(Socket, Pid) -> yes | no when
    Socket :: gen_quic:socket() |
              {Socket, balancer},
    Pid :: pid().

register_name({Socket, balancer}, Pid) ->
  ets:update_element(?TABLE, Socket, {2, Pid}),
  yes;

register_name({Socket, Stream}, Pid) ->
  Stream_Map = ets:lookup_element(?TABLE, Socket, 3),
  ets:update_element(?TABLE, Socket, {3, Stream_Map#{Stream => Pid}}),
  yes;

register_name(Socket, Pid) ->
  ets:insert(?TABLE, {Socket, {Pid, undefined, #{}}}),
  yes.


-spec register_stream(Stream, Pid) -> yes | no when
    Stream :: gen_quic:stream(),
    Pid :: pid().

register_stream({Socket, Stream_ID}, Pid) ->
  Stream_Map = ets:lookup_element(?TABLE, Socket, 3),
  ets:update_element(?TABLE, Socket, {3, Stream_Map#{Stream_ID => Pid}}),
  yes.


-spec register_conn_id(Socket, Conn_ID) -> yes | no when
    Socket :: gen_quic:socket(),
    Conn_ID :: binary().

register_conn_id(Socket, Conn_ID) ->
  case ets:lookup(?CONN_TABLE, Conn_ID) of
    [] ->
      ets:insert_new(?CONN_TABLE, {Conn_ID, Socket}),
      yes;
    _ ->
      %% A connection id of that name has already been registered.
      no
  end.


-spec unregister_name(Socket) -> ok when
    Socket :: gen_quic:socket().

unregister_name(Socket) ->
  ets:delete(?TABLE, Socket).
  %% case ets:lookup_element(?TABLE, Socket, 3) of
  %%   #{} ->
  %%     %% If the stream map is empty, then remove it.
  %%     ets:delete(?TABLE, Socket),
  %%     ok;
  %%   _ ->
  %%     %% Otherwise there are existing streams and an error has to be thrown. (for now).
  %%     %% This should probably tell all the streams and balancer to close instead with an internal error.
  %%     erlang:error("Socket cannot be closed when streams are still open", Socket)
  %% end.


-spec unregister_stream(Stream) -> ok when
    Stream :: gen_quic:stream().

unregister_stream({Socket, Stream_ID}) ->
  %% The stream is removed from the sockets map of streams.
  Stream_Map = ets:lookup_element(?TABLE, Socket, 3),
  New_Map = maps:remove(Stream_ID, Stream_Map),
  ets:update_element(?TABLE, Socket, {3, New_Map}),
  ok.


-spec unregister_conn_id(Conn_ID) -> ok when
    Conn_ID :: binary().

unregister_conn_id(Conn_ID) ->
  ets:delete(?CONN_TABLE, Conn_ID),
  ok.


-spec whereis_name(Socket) -> Result when
    Socket :: gen_quic:socket() |
              {Socket, balancer},
    Result :: pid() | undefined.

whereis_name({Socket, balancer}) ->
  case ets:lookup(?TABLE, Socket) of
    [] ->
      undefined;
    [{Socket, {_, Pid, _}}] ->
      Pid
  end;

whereis_name({Socket, Stream}) ->
  case ets:lookup(?TABLE, Socket) of
    [] ->
      undefined;
    [{Socket, {_, _, Stream_Map}}] ->
      maps:get(Stream, Stream_Map, undefined)
  end;

whereis_name(Socket) ->
  case ets:lookup(?TABLE, Socket) of
    [] ->
      undefined;
    [{Socket, {Pid, _, _}}] ->
      Pid
  end.


-spec whereis_conn_id(Conn_ID) -> undefined | Socket when
    Conn_ID :: binary(),
    Socket :: gen_quic:socket().

whereis_conn_id(Conn_ID) ->
  case ets:lookup(?CONN_TABLE, Conn_ID) of
    [] ->
      undefined;
    [Socket] ->
      Socket
  end.


-spec send(Socket, Message) -> Result when
    Socket :: gen_quic:socket(),
    Message :: term(),
    Result :: ok.

send(Socket, Msg) ->
  case whereis_name(Socket) of
    Pid when is_pid(Pid) ->
      Pid ! Msg,
      ok;
    
    undefined ->
      {error, not_found}
      %% exit({badarg, {Socket, Msg}})
  end.




%%%===================================================================
%%% Internal functions
%%%===================================================================


