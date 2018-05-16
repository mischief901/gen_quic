%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%%
%%% @end
%%% Created : 16 May 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_prim).

%% API

-export([connect/4]).
-export([listen/3]).
-export([accept/2]).
-export([shutdown/1]).
-export([sendto/2]).
-export([recvfrom/3]).

%%%===================================================================
%%% API
%%%===================================================================

connect(Address, Port, Opts, Timeout) ->
    ok.

listen(Port, Opts, Timeout) ->
    ok.

accept(Socket, Timeout) ->
    ok.

shutdown(Socket) ->
    ok.

sendto(Socket, Packet) ->
    case quic_db:getaddr(Socket) of
	{ok, {IP, Port}} ->
	    prim_inet:sendto(Socket, IP, Port, Packet);
	Error ->
	    Error
    end.

recvfrom(Socket, Length, Timeout) ->
    prim_inet:recvfrom(Socket, Length, Timeout).

%%%===================================================================
%%% Internal functions
%%%===================================================================
