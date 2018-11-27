%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%%
%%% @end
%%% Created :  9 Nov 2018 by alex <alex@alex-Lenovo>

-module(ping_client).


-export([start/2]).

start(IP, Port) ->
  {ok, Socket} = gen_quic:connect(IP, Port, []),
  {ok, Stream} = gen_quic:open(Socket),
  gen_quic:send(Stream, "Ping"),
  loop(Socket, Stream, self()).

loop(Socket, Stream, Owner) ->
  receive
    {stream_data, Stream, Data} ->
      io:format("~a~n", [Data]),
      erlang:sleep(1000),
      gen_quic:send(Stream, Data),
      loop(Socket, Stream, Owner);
    stream_close ->
