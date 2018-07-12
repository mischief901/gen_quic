%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, Alex Misch
%%% @doc
%%% The API for creating and using a QUIC socket and connection.
%%% Calls the inet_quic.erl module for most functions; similar to gen_udp.erl
%%% calling inet_udp.erl and gen_tcp.erl calling inet_tcp.erl. Only IPv4 is
%%% supported at the moment, but this allows for better future support of IPv6.
%%% @end
%%% Created : 14 May 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(gen_quic).

%% API
%% These will change as the module comes together
-export([connect/3, connect/4]).
-export([listen/2]).
-export([accept/1, accept/2]).
-export([open/2]).
-export([close/1, shutdown/2]).
-export([send/2]).
-export([recv/2, recv/3]).
-export([controlling_process/2]).

-include("inet_int.hrl").

-type socket() :: inet:socket() |
                  {inet:socket(), StreamID :: non_neg_integer()}.


-type option() ::
        {active, true | false | once | -32768..32767} |
        {add_membership, {inet:ip_address(), inet:ip_address()}} |
        {broadcast, boolean()} |
        {buffer, non_neg_integer()} |
        {deliver, port | term} |
        {dontroute, boolean()} |
        {drop_membership, {inet:ip_address(), inet:ip_address()}} |
        {header, non_neg_integer()} |
        {high_msgq_watermark, pos_integer()} |
        {low_msgq_watermark, pos_integer()} |
        {mode, list | binary} | list | binary |
        {multicast_if, inet:ip_address()} |
        {multicast_loop, boolean()} |
        {multicast_ttl, non_neg_integer()} |
        {priority, non_neg_integer()} |
        {raw,
         Protocol :: non_neg_integer(),
         OptionNum :: non_neg_integer(),
         ValueBin :: binary()} |
        {read_packets, non_neg_integer()} |
        {recbuf, non_neg_integer()} |
        {reuseaddr, boolean()} |
        {sndbuf, non_neg_integer()} |
        {tos, non_neg_integer()} |
        {ipv6_v6only, boolean()}.

-type option_name() ::
        active |
        broadcast |
        buffer |
        deliver |
        dontroute |
        header |
        high_msgq_watermark |
        low_msgq_watermark |
        mode |
        multicast_if |
        multicast_loop |
        multicast_ttl |
        priority |
        {raw,
         Protocol :: non_neg_integer(),
         OptionNum :: non_neg_integer(),
         ValueSpec :: (ValueSize :: non_neg_integer()) |
                      (ValueBin :: binary())} |
        read_packets |
        recbuf |
        reuseaddr |
        sndbuf |
        tos |
        ipv6_only.

-export_type([option/0, option_name/0, socket/0]).

%%%===================================================================
%%% API
%%%===================================================================

%%
%% Connect: Probably the correct way to go about opening these sockets.
%% Based on gen_tcp.
%%

-spec connect(Address, Port, Opts) -> {ok, Socket} | {error, Reason} when
    Address :: inet:socket_address() | inet:hostname(),
    Port :: inet:port_number(),
    Opts :: [Option],
    Option :: {ip, inet:socket_address()} |
              {fd, non_neg_integer()} |
              {ifaddr, inet:socket_address()} |
              inet:address_family() |
              {port, inet:port_number()} |
              option(),
    Socket :: socket(),
    Reason :: inet:posix().

connect(Address, Port, Opts) ->
  connect(Address, Port, Opts, infinity).

-spec connect(Address, Port, Opts, Timeout) -> 
                 {ok, Socket} | {error, Reason} when
    Address :: inet:socket_address() | inet:hostname(),
    Port :: inet:port_number(),
    Opts :: [Option],
    Option :: {ip, inet:socket_address()} |
              {fd, non_neg_integer()} |
              {ifaddr, inet:socket_address()} |
              inet:address_family() |
              {port, inet:port_number()} |
              option(),
    Timeout :: timeout(),
    Socket :: socket(),
    Reason :: inet:posix().

connect(Address, Port, Opts, Time) ->
  Timer = inet:start_timer(Time),
  Res = (catch connect1(Address, Port, Opts, Timer)),
  _ = inet:stop_time(Timer),
  case Res of
    {ok, Socket} ->
      {ok, Socket};
    {error, einval} ->
      exit(badarg);
    {'EXIT', Reason} ->
      exit(Reason);
    Error ->
      Error
  end.

connect1(Address, Port, Opts0, Timer) ->
  {Mod, Opts} = inet_quic_util:quic_module(Opts0, Address),
  case Mod:getaddrs(Address, Timer) of
    {ok, IPs} ->
      case Mod:getserv(Port) of
        {ok, QPort} ->
          try_connect(IPs, QPort, Opts, Timer, Mod, {error, einval});
        Error ->
          Error
      end;
    Error ->
      Error
  end.

try_connect([IP | IPs], Port, Opts, Timer, Mod, _) ->
  Time = inet:timeout(Timer),
  case Mod:connect(IP, Port, Opts, Time) of
    {ok, Socket} ->
      {ok, Socket};
    {error, einval} ->
      {error, einval};
    {error, timeout} ->
      {error, timeout};
    Err1 ->
      try_connect(IPs, Port, Opts, Timer, Mod, Err1)
  end;
try_connect([], _Port, _Opts, _Timer, _Mod, Err) ->
  Err.


%%
%% Listen on a port for a QUIC Connection.
%%

-spec listen(Port, Opts) -> {ok, Socket} | {error, Reason} when
    Port :: inet:port_number(),
    Opts :: [Option],
    Option :: {ip, inet:socket_address()} |
              {fd, non_neg_integer()} |
              {ifaddr, inet:socket_address()} |
              inet:address_family() |
              {port, inet:port_number()} |
              option(),
    Socket :: socket(),
    Reason :: system_limit | inet:posix().

listen(Port, Opts0) ->
  {Mod, Opts} = inet_quic_util:quic_module(Opts0),
  case Mod:getserv(Port) of
    {ok, QPort} ->
      Mod:listen(QPort, Opts);
    {error, einval} ->
      exit(badarg);
    Other ->
      Other
  end.

%%
%% Accept a QUIC listen socket request
%%

-spec accept(PeerSocket) -> {ok, Socket} | {error, Reason} when
    PeerSocket :: socket(),
    Socket :: socket(),
    Reason :: closed | timeout | system_limit | inet:posix().
%% Maybe not closed because of reconnection.

accept(PeerSocket) ->
  case inet_db:lookup_socket(PeerSocket) of
    {ok, Mod} ->
      Mod:accept(PeerSocket);
    Error ->
      Error
  end.


-spec accept(PeerSocket, Timeout) -> {ok, Socket} | {error, Reason} when
    PeerSocket :: socket(),
    Timeout :: timeout(),
    Socket :: socket(),
    Reason :: closed | timeout | system_limit | inet:posix().
%% Maybe not closed because of reconnection.

accept(PeerSocket, Timeout) ->
  case inet_db:lookup_socket(PeerSocket) of
    {ok, Mod} ->
      Mod:accept(PeerSocket, Timeout);
    Error ->
      Error
  end.


-spec open(Socket, Opts) -> Result when
    Socket :: port(),
    Opts :: [Opt],
    Opt :: gen_quic:stream_options(),
    Result :: {ok, {Socket, StreamID}} | {error, Reason},
    StreamID :: non_neg_integer(),
    Reason :: inet:posix().

open(Socket, Opts) ->
  case inet_db:lookup_socket(Socket) of
    {ok, Mod} ->
      Mod:open(Socket, Opts);
    Error ->
      Error
  end.

%%
%% Close
%%

-spec close(Socket) -> ok when
    Socket :: socket().

close(Socket) ->
  inet_quic_util:close(Socket).


%% 
%% Shutdown: Used to close streams.
%%

-spec shutdown({Socket, Stream_ID}) -> ok | {error, Reason} when
    Socket :: socket(),
    Stream_ID :: non_neg_integer(),
    Reason :: inet:posix().

shutdown({Socket, Stream_ID}) ->
  case inet_db:lookup_socket(Socket) of
    {ok, Mod} ->
      Mod:shutdown({Socket, Stream_ID});
    Error ->
      Error
  end.


%%
%% Send
%%

-spec send(Socket, Packet) -> ok | {error, Reason} when
    Socket :: socket(),
    Stream_ID :: non_neg_integer(),
    Packet :: iodata(),
    Reason :: closed | inet:posix().

send({Socket, Stream_ID}, Packet) ->
  case inet_db:lookup_socket(Socket) of
    {ok, Mod} ->
      Mod:send({Socket, Stream_ID}, Packet);
    Error ->
      Error
  end;

send(Socket, Packet) ->
  case inet_db:lookup_socket(Socket) of
    {ok, Mod} ->
      Mod:send(Socket, Packet);
    Error ->
      Error
  end.


%%
%% Recv
%%

-spec recv(Socket, Length) -> {ok, Packet} | {error, Reason} when
    Socket :: socket(),
    Length :: non_neg_integer(),
    Packet :: string() | binary() | HttpPacket,
    Reason :: closed | not_owner | inet:posix(),
    HttpPacket :: term().

recv({Socket, Stream_ID}, Length) when is_integer(Length) ->
  case inet_db:lookup_socket(Socket) of
    {ok, Mod} ->
      Mod:recv({Socket, Stream_ID}, Length);
    Error ->
      Error
  end;

recv(Socket, Length) when is_integer(Length) ->
  case inet_db:lookup_socket(Socket) of
    {ok, Mod} ->
      Mod:recv(Socket, Length);
    Error ->
      Error
  end.

-spec recv(Socket, Length, Timeout) -> {ok, Packet} | {error, Reason} when
    Socket :: socket(),
    Length :: non_neg_integer(),
    Timeout :: timeout(),
    Packet :: string() | binary(),
    Reason :: closed | not_owner | inet:posix().

recv({Socket, Stream_ID}, Length, Timeout) when is_integer(Length) ->
  case inet_db:lookup_socket(Socket) of
    {ok, Mod} ->
      Mod:recv({Socket, Stream_ID}, Length, Timeout);
    Error ->
      Error
  end;

recv(Socket, Length, Timeout) when is_integer(Length) ->
  case inet_db:lookup_socket(Socket) of
    {ok, Mod} ->
      Mod:recv(Socket, Length, Timeout);
    Error ->
      Error
  end.


%%%===================================================================
%%% Internal functions
%%%===================================================================
