%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%% The IPv4 QUIC module. Also include some helper functions like 
%%% getserv and getaddr. See inet6_quic.erl for the IPv6 QUIC module.
%%% This module checks for IPv4 compatibility and reduces functions to
%%% the single arity ones called in quic_prim.erl.
%%% @end
%%% Created : 15 May 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(inet_quic).

%% API: Will change as module comes together
-export([getserv/1, getaddr/1, getaddr/2, getaddrs/1, getaddrs/2]).
-export([connect/3, connect/4]).
-export([listen/2, listen/3]).
-export([accept/1, accept/2]).
-export([shutdown/1]).
-export([recv/2, recv/3]).
-export([send/2]).

-define(FAMILY, inet).
-define(PROTO, quic).

%%%===================================================================
%%% API
%%%===================================================================

-spec getserv(Port) -> {ok, QPort} | {error, Reason} when
    Port :: inet:port_number(),
    QPort :: inet:port_number(),
    Reason :: system_limit | inet:posix().

getserv(Port) when is_integer(Port) ->
  {ok, Port};
getserv(Name) when is_atom(Name) ->
  inet_quic_util:getservbyname(Name, ?PROTO).


-spec getaddr(Address) -> {ok, IP} | {error, Reason} when
    Address :: inet:socket_address() | inet:hostname(),
    IP :: inet:ip_address(),
    Reason :: inet:posix().

getaddr(Address) ->
  inet:getaddr(Address, ?FAMILY).

-spec getaddr(Address, Timer) -> {ok, IPs} | {error, Reason} when
    Address :: inet:socket_address() | inet:hostname(),
    Timer :: non_neg_integer(),
    IPs :: [IP],
    IP :: inet:ip_address(),
    Reason :: inet:posix().

getaddr(Address, Timer) ->
  inet:getaddr_tm(Address, ?FAMILY, Timer).

-spec getaddrs(Address) -> {ok, IP} | {error, Reason} when
    Address :: inet:socket_address() | inet:hostname(),
    IP :: inet:ip_address(),
    Reason :: inet:posix().

getaddrs(Address) ->
  inet:getaddrs(Address, ?FAMILY).

-spec getaddrs(Address, Timer) -> {ok, IPs} | {error, Reason} when
    Address :: inet:socket_address() | inet:hostname(),
    Timer :: non_neg_integer(),
    IPs :: [IP],
    IP :: inet:ip_address(),
    Reason :: inet:posix().

getaddrs(Address, Timer) ->
  inet:getaddrs_tm(Address, ?FAMILY, Timer).


-spec connect(Address, Port, Opts) -> Result when
    Address :: inet:ip_address(),
    Port :: inet:port_number(),
    Opts :: [Opt],
    Opt :: gen_quic:option(),
    Result :: {ok, Socket} | {error, Reason},
    Socket :: inet:socket(),
    Reason :: inet:posix().

connect(Address, Port, Opts) ->
  connect(Address, Port, Opts, infinity).

-spec connect(Address, Port, Opts, Timeout) -> Result when
    Address :: inet:ip_address(),
    Port :: inet:port_number(),
    Opts :: [Opt],
    Opt :: gen_quic:option(),
    Timeout :: non_neg_integer(),
    Result :: {ok, Socket} | {error, Reason},
    Socket :: inet:socket(),
    Reason :: timeout | inet:posix().

connect(Address, Port, Opts, Timeout) ->
  quic_conn:connect(Address, Port, Opts, Timeout).


-spec listen(Port, Opts) -> Result when
    Port :: inet:port_number(),
    Opts :: [Opt],
    Opt :: gen_quic:option(),
    Result :: {ok, Socket} | {error, Reason},
    Socket :: inet:socket(),
    Reason :: inet:posix().

listen(Port, Opts) ->
  listen(Port, Opts, infinity).

-spec listen(Port, Opts, Timeout) -> Result when
    Port :: inet:port_number(),
    Opts :: [Opt],
    Opt :: gen_quic:options(),
    Timeout :: non_neg_integer(),
    Result :: {ok, Socket} | {error, Reason},
    Socket :: inet:socket(),
    Reason :: timeout | inet:posix().

listen(Port, Opts, Timeout) ->
  quic_conn:listen(Port, Opts, Timeout).


-spec accept(Socket) -> Result when
    Socket :: inet:socket(),
    Result :: {ok, Socket} | {error, Reason},
    Reason :: timeout | inet:posix().

accept(Socket) ->
  accept(Socket, infinity).

-spec accept(Socket, Timeout) -> Result when
    Socket :: inet:socket(),
    Timeout :: non_neg_integer(),
    Result :: {ok, Socket} | {error, Reason},
    Reason :: timeout | inet:posix().

accept(Socket, Timeout) ->
  quic_conn:accept(Socket, Timeout).


-spec recv(Socket, Length) -> {ok, Packet} | {error, Reason} when
    Socket :: inet:socket(),
    Length :: non_neg_integer(),
    Packet :: string() | binary() | iodata(),
    Reason :: timeout | closed | inet:posix().

recv(Socket, Length) ->
  recv(Socket, Length, infinity).

-spec recv(Socket, Length, Timeout) -> Result when
    Socket :: gen_quic:socket(),
    Length :: non_neg_integer(),
    Timeout :: non_neg_integer(),
    Result :: {ok, Packet} | {error, Reason},
    Packet :: string() | binary(),
    Reason :: timeout | closed | inet:posix().

recv(Socket, Length, Timeout) ->
  quic_conn:recv(Socket, Length, Timeout).


-spec send(Socket, Packet) -> Result when
    Socket :: inet:socket(),
    Packet :: string() | binary() | iodata(),
    Result :: ok | {error, Reason},
    Reason :: closed | inet:posix().

send(Socket, Packet) ->
  quic_conn:send(Socket, Packet).


-spec close(Socket) -> Result when
    Socket :: gen_quic:socket(),
    Result :: ok | {error, Reason},
    Reason :: inet:posix() | closed | not_owner.

close(Socket) ->
  quic_conn:close(Socket).


-spec shutdown({Socket, Stream_ID}) -> Result when
    Socket :: gen_quic:socket(),
    Stream_ID :: non_neg_integer(),
    Result :: ok | {error, Reason},
    Reason :: inet:posix() | closed | not_owner.

shutdown(Stream) ->
  quic_conn:shutdown(Stream).

%%%===================================================================
%%% Internal functions
%%%===================================================================
