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
-export([start/0]).
-export([connect/3, connect/4]).
-export([listen/2]).
-export([accept/1, accept/2]).
-export([open/2]).
-export([close/1]).
-export([send/2]).
-export([recv/2, recv/3]).
-export([controlling_process/2]).

-export([setopts/2, getopts/2]).
%% -export([set_stream_opts/2, get_stream_opts/2]).


-type socket() :: port().

-type stream() :: {socket(), StreamID :: non_neg_integer()}.

-type stream_option() ::
        #{pack => none | low | balanced,
          type => uni | bidi,
          stream_data_limit => non_neg_integer(),
          active => true | false | once | -32768..32767,
          mode => list | binary,
          stream_timeout => non_neg_integer() | infinity
         }.

-type balancer_option() ::
        #{init_stream_id_bidi => non_neg_integer(),
          init_stream_id_uni  => non_neg_integer(),
          stream_id_incr_bidi => non_neg_integer(),
          stream_id_incr_uni  => non_neg_integer(),
          max_stream_id_bidi  => non_neg_integer(),
          max_stream_id_uni   => non_neg_integer(),
          default_stream_opts => stream_option()
         }.

-type option() ::
        gen_udp:option() |
        {packing_priority, none | low | balanced} |
        {balancer_opts, balancer_option()}.

-type option_name() ::
        pack |
        type |
        stream_data_limit |
        active |
        mode | list | binary |
        init_stream_id_bidi |
        init_stream_id_uni |
        stream_id_incr_bidi |
        stream_id_incr_uni |
        max_stream_id_bidi |
        max_stream_id_uni |
        default_stream_opts |
        packing_priority |
        balancer_opts.

%% These will be expanded later.
-type error() ::
        any().

-type frame_error() :: 
        any().

-export_type([stream_option/0, balancer_option/0, option/0, option_name/0]).
-export_type([error/0, frame_error/0]).
-export_type([socket/0, stream/0]).

%%%===================================================================
%%% API
%%%===================================================================


-spec start() -> ok.
start() ->
  crypto:start(),
  quic_registry:start(),
  quic_vxx:start_link([]),
  ok.

%%
%% Connect: Probably the correct way to go about opening these sockets.
%% Based on gen_tcp.
%%

-spec connect(Address, Port, Opts) -> {ok, Socket} | {error, Reason} when
    Address :: inet:socket_address() | inet:hostname(),
    Port :: inet:port_number(),
    Opts :: [Option],
    Option :: option(),
    Socket :: socket(),
    Reason :: error().

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
  Res = connect1(Address, Port, Opts, Timer),
  _ = inet:stop_timer(Timer),
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
    {ok, inet_udp} ->
      inet_quic:accept(PeerSocket);
    %% {ok, inet6_udp} ->
    %% Not implemented yet.
    %%   inet6_quic:accept(PeerSocket);
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
    {ok, _Mod} ->
      inet_quic:accept(PeerSocket, Timeout);
    Error ->
      Error
  end.


-spec open(Socket, Opts) -> Result when
    Socket :: port(),
    Opts :: [Opt],
    Opt :: gen_quic:stream_option(),
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


-spec close(Socket) -> ok | {error, Reason} when
    Socket :: socket() | {socket(), Stream_ID},
    Stream_ID :: non_neg_integer(),
    Reason :: not_owner.

close({Socket, Stream_ID}) ->
  case inet_db:lookup_socket(Socket) of
    {ok, Mod} ->
      Mod:close({Socket, Stream_ID});
    Error ->
      Error
  end;

close(Socket) ->
  case inet_db:lookup_socket(Socket) of
    {ok, Mod} ->
      Mod:close(Socket);
    Error ->
      Error
  end.

%%
%% Send
%%

-spec send(Socket, Packet) -> ok | {error, Reason} when
    Socket :: socket(),
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


-spec controlling_process(Socket, Pid) -> ok | {error, Reason} when
    Socket :: socket(),
    Pid :: pid(),
    Reason :: not_owner | closed | badarg.

controlling_process(Socket, Pid) ->
  quic_conn:controlling_process(Socket, Pid).


-spec setopts(Socket, Options) -> Result when 
    Socket :: gen_quic:socket(),
    Options :: [Option],
    Option :: gen_quic:option() | gen_udp:option(),
    Result :: ok |
              {error, [Errors]},
    Errors :: {invalid_option, gen_quic:option()} |
              {unknown_option, term()}.

setopts(Socket, Options) ->
  quic_conn:setopts(Socket, Options).


-spec getopts(Socket, Options) -> Result when
    Socket :: gen_quic:socket(),
    Result :: {error, socket_not_found} |
              {ok, Options},
    Options :: [Option],
    Option :: gen_quic:option() | gen_udp:option().

getopts(Socket, Options) ->
  quic_conn:getopts(Socket, Options).





%%%===================================================================
%%% Internal functions
%%%===================================================================
