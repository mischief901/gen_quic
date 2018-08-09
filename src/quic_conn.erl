%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%% The quic_conn module creates a new quic connection and
%%% allows for multiplexing/demultiplexing across the connection
%%% by creating streams. See the quic_stream module for details 
%%% on individual stream processes.
%%% quic_conn has the apis for the quic_server and quic_client state machines
%%% accept spawns a gen_statem with quic_server as the callback module and 
%%% connect spawns a gen_statem with quic_client as the callback module.
%%% Both quic_server and quic_client import common functions from this module.
%%% @end
%%% Created : 29 Jun 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_conn).

-export([connect/4]).
-export([listen/2]).
-export([accept/3]).
-export([open/2]).
-export([send/2]).
-export([recv/3]).
-export([controlling_process/2]).
-export([close/1]).

-include("quic_headers.hrl").


%%%===================================================================
%%% API
%%%===================================================================

-spec connect(Address, Port, Opts, Timeout) -> Result when
    Address :: inet:address(),
    Port :: inet:port_number(),
    Opts :: [Opt],
    Opt :: gen_quic:option(),
    Timeout :: non_neg_integer(),
    Result :: {ok, Socket} | {error, Reason},
    Socket :: inet:socket(),
    Reason :: inet:posix().

connect(Address, Port, Opts, Timeout) ->
  {ok, Quic_Opts} = inet_quic_util:parse_opts(Opts),

  %% This socket should remain active regardless of the options.
  {ok, Socket} = inet_udp:open([{active, true} | Opts]),
  
  Data = #quic_data{
            type = client,
            conn = #quic_conn{
                      socket = Socket,
                      owner = self()
                     }
           },

  {ok, Pid} = gen_statem:start_link(via(Socket), quic_client,
                                    [Data, Quic_Opts], []),
  
  inet_udp:controlling_process(Socket, Pid),
  
  gen_statem:call(Pid, {connect, Address, Port, Timeout}).


-spec listen(Port, Opts) -> Result when
    Port :: inet:port_number(),
    Opts :: [Opt],
    Opt :: gen_quic:option(),
    Result :: {ok, Socket} | {error, Reason},
    Socket :: gen_quic:socket(),
    Reason :: inet:posix().

listen(Port, Opts) ->
  inet_udp:open(Port, Opts).


-spec accept(LSocket, Timeout, Options) -> Result when
    LSocket :: gen_quic:socket(),
    Timeout :: non_neg_integer(),
    Options :: [Option],
    Option :: gen_quic:options(),
    Result :: {ok, Socket} | {error, Reason},
    Socket :: gen_quic:socket(),
    Reason :: inet:posix() | timeout.

accept(LSocket, Timeout, Opts) ->
  
  {ok, Quic_Opts} = inet_quic_util:parse_opts(Opts),

  %% This socket should remain active regardless of the options.
  {ok, Socket} = inet_udp:open([{active, true} | Opts]),
  
  
  Data = #quic_data{
            type = server,
            conn = #quic_conn{
                      socket = Socket,
                      owner = self()
                     }
           },

  {ok, Pid} = gen_statem:start_link(via(Socket), quic_server,
                                    [Data, Quic_Opts], []),
  
  inet_udp:controlling_process(Socket, Pid),
  
  gen_statem:call(Pid, {accept, LSocket, Timeout}).

%% TODO: update for new quic_client/quic_server modules.
%% Should probably be the start_link or start for the quic_stream gen_server.
%% Opens a new stream on the given Socket.
-spec open(Socket, Opts) -> Result when
    Socket :: gen_quic:socket(),
    Opts :: [Opt],
    Opt :: gen_quic:socket_option(),
    Result :: {ok, Stream} | {error, Reason},
    Stream :: {Socket, Stream_ID},
    Stream_ID :: non_neg_integer(),
    Reason :: gen_quic:errors().

open(Socket, Opts) ->
  %% Something like this. The gen_statem opens the quic_stream gen_server so it
  %% can trap and manage exits and open streams when receiving an open stream frame
  case gen_statem:call(via(Socket), {open_stream, Opts}) of
    {ok, Stream_ID} ->
      {ok, {Socket, Stream_ID}};
    
    {error, Reason} ->
      {error, Reason}
  end.

-spec send(Socket, Message) -> ok when
    Socket :: gen_quic:socket(),
    Message :: binary().

send(Socket, Message) when is_tuple(Socket) ->
  %% For streams.
  gen_server:cast(Socket, {send, Message});

send(Socket, Message) ->
  gen_statem:cast(via(Socket), {send, Message}).

%% Packet Length is ignored since it is a datagram.
-spec recv(Socket, Length, Timeout) -> Result when
    Socket :: gen_quic:socket(),
    Length :: non_neg_integer(),
    Timeout :: non_neg_integer() | infinity,
    Result :: {ok, Data} | {error, Reason},
    Data :: list() | binary(),
    Reason :: inet:posix() | timeout.

recv(Socket, _Length, Timeout) when is_tuple(Socket) ->
  %% For streams.
  gen_server:call(via(Socket), recv, Timeout);

recv(Socket, _Length, Timeout) ->
  gen_statem:call(via(Socket), recv, Timeout).


-spec controlling_process(Socket, Pid) -> Result when
    Socket :: gen_quic:socket(),
    Pid :: pid(),
    Result :: ok | {error, Reason},
    Reason :: closed | not_owner | badarg | inet:posix().

controlling_process(Socket, Pid) when is_tuple(Socket) ->
  gen_server:call(via(Socket), {controlling_process, Pid});

controlling_process(Socket, Pid) ->
  gen_statem:call(via(Socket), {controlling_process, Pid}).


-spec close(Socket) -> ok when
    Socket :: gen_quic:socket().

close(Socket) when is_tuple(Socket) ->
  gen_server:cast(via(Socket), close);

close(Socket) ->
  gen_statem:cast(via(Socket), close).



via(Socket) ->
  {via, quic_registry, Socket}.
