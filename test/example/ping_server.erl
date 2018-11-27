%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%%
%%% @end
%%% Created :  9 Nov 2018 by alex <alex@alex-Lenovo>

-module(ping_server).

-export([start/1]).
-export([ping_stream/2]).

start(Port) ->
  {ok, LSocket} = gen_quic:listen(Port, [binary, {active, true}]),
  {ok, Socket} = gen_quic:accept(LSocket),
  loop(Socket, self()).

loop(Socket, Owner) ->
  receive
    {stream_open, Stream} ->
      spawn_link(ping_server, ping_stream, [Owner, Stream]),
      loop(Socket, Owner);
    {stream_close, {Socket, Stream_ID}} ->
      io:format("Stream ~a shutdown.~n", [Stream_ID]),
      loop(Socket, Owner);
    close ->
      gen_quic:close(Socket),
      ok
  end.

ping_stream(Owner, Stream) ->
  receive
    {stream_data, Info} ->
      io:format("~a~n", [Info]),
      gen_quic:send(Stream, "Pong"),
      ping_stream(Owner, Stream);
    stream_close ->
      Owner ! {stream_close, Stream},
      ok
  end.
