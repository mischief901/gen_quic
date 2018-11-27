%%%-------------------------------------------------------------------
%%% @author alex
%%% @copyright (C) 2018, alex
%%% @doc
%%% The IPv4 QUIC module. Also include some helper functions like 
%%% getserv and getaddr. See inet6_quic.erl for the IPv6 QUIC module.
%%% This module checks for IPv4 compatibility and reduces functions to
%%% the single arity ones called in quic_prim.erl.
%%% @end
%%%-------------------------------------------------------------------
-module(inet_quic).

%% API: Will change as module comes together
-export([getserv/1, getaddr/1, getaddr/2, getaddrs/1, getaddrs/2]).
-export([connect/3, connect/4]).
-export([listen/2]).
-export([accept/1, accept/2]).
-export([close/1]).
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

-spec getaddr(Address, Timer) -> {ok, IP} | {error, Reason} when
    Address :: inet:socket_address() | inet:hostname(),
    Timer :: non_neg_integer(),
    IP :: inet:ip_address(),
    Reason :: inet:posix().

getaddr(Address, Timer) ->
  inet:getaddr_tm(Address, ?FAMILY, Timer).

-spec getaddrs(Address) -> {ok, [IPs]} | {error, Reason} when
    Address :: inet:socket_address() | inet:hostname(),
    IPs :: [IP],
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
    Socket :: gen_quic:socket(),
    Reason :: gen_quic:error().

connect(Address, Port, Opts) ->
  connect(Address, Port, Opts, infinity).

-spec connect(Address, Port, Opts, Timeout) -> Result when
    Address :: inet:ip_address(),
    Port :: inet:port_number(),
    Opts :: [Opt],
    Opt :: gen_quic:option(),
    Timeout :: non_neg_integer() | infinity,
    Result :: {ok, Socket} | {error, Reason},
    Socket :: gen_quic:socket(),
    Reason :: timeout | inet:posix().

connect(Address, Port, Opts, Timeout) ->
  quic_conn:connect(Address, Port, Opts, Timeout).


-spec listen(Port, Opts) -> Result when
    Port :: inet:port_number(),
    Opts :: [Opt],
    Opt :: gen_quic:option(),
    Result :: {ok, Socket} | {error, Reason},
    Socket :: gen_quic:socket(),
    Reason :: inet:posix().

listen(Port, Opts) ->
  quic_conn:listen(Port, Opts).

-spec accept(Socket) -> Result when
    Socket :: gen_quic:socket(),
    Result :: {ok, Socket} | {error, Reason},
    Reason :: timeout | inet:posix().

accept(Socket) ->
  accept(Socket, infinity).

-spec accept(Socket, Timeout) -> Result when
    Socket :: gen_quic:socket(),
    Timeout :: non_neg_integer() | infinity,
    Result :: {ok, Socket} | {error, Reason},
    Reason :: timeout | inet:posix().

accept(Socket, Timeout) ->
  quic_conn:accept(Socket, Timeout, []).


-spec recv(Socket, Length) -> {ok, Packet} | {error, Reason} when
    Socket :: gen_quic:socket() | gen_quic:stream(),
    Length :: non_neg_integer(),
    Packet :: string() | binary() | iodata(),
    Reason :: timeout | closed | inet:posix().

recv(Socket, Length) ->
  recv(Socket, Length, infinity).

-spec recv(Socket, Length, Timeout) -> Result when
    Socket :: gen_quic:socket() | gen_quic:stream(),
    Length :: non_neg_integer(),
    Timeout :: non_neg_integer() | infinity,
    Result :: {ok, Packet} | {error, Reason},
    Packet :: string() | binary(),
    Reason :: timeout | closed | inet:posix().

recv(Socket, Length, Timeout) ->
  quic_conn:recv(Socket, Length, Timeout).


-spec send(Socket, Info) -> ok when
    Socket :: gen_quic:socket() | gen_quic:stream(),
    Info :: string() | binary() | iodata().

send(Socket, Info) ->
  quic_conn:send(Socket, Info).


-spec close(Socket) -> Result when
    Socket :: gen_quic:socket() | gen_quic:stream(),
    Result :: ok | {error, not_owner}.

close(Socket) ->
  quic_conn:close(Socket).


%%%===================================================================
%%% Internal functions
%%%===================================================================
