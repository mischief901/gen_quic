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

-export([open/1, open/2]).
-export([sendto/2]).
-export([recvfrom/2]).
-export([connect/3]).
-export([controlling_process/2]).

-include("quic_headers.hrl").

%%%===================================================================
%%% API
%%%===================================================================

%% TODO: Add more error handling. Check args and funs in prim_inet.

open(Port) when is_integer(Port) ->
  open(Port, []);
open(Opts) when is_list(Opts) ->
  open(0, Opts).

open(Port, Opts) ->
  ?DBG("Calling open on ~p in prim_inet.~n", [Port]),
  prim_inet:open(Port, Opts).


sendto(Socket, Packet) ->
  %% Socket is connected so the destination IP and Port should be bound to 
  %% socket.
  ?DBG("Calling sendto on ~p in prim_inet.~n", [Socket]),
  prim_inet:sendto(Socket, Packet).


recvfrom(Socket, Timeout) ->
  ?DBG("Calling recvfrom on ~p in prim_inet.~n", [Socket]),
  prim_inet:recvfrom(Socket, 0, Timeout).


connect(Socket, IP, Port) ->
  %% Bind the destination IP and Port to the socket.
  ?DBG("Calling connect on ~p to ~p:~p in prim_inet.~n", [Socket, IP, Port]),
  prim_inet:connect(Socket, IP, Port, infinity).


controlling_process(Socket, Pid) ->
  ?DBG("Calling controlling_process on ~p to ~p in prim_inet.~n", [Socket, Pid]),
  prim_inet:controlling_process(Socket, Pid).


%%%===================================================================
%%% Internal functions
%%%===================================================================
