%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%% The quic_conn module creates a new quic connection and
%%% allows for multiplexing/demultiplexing across the connection
%%% by creating streams. See the quic_stream module for details 
%%% on individual stream processes. Calls the quic_server module
%%% for accept and listen functions.
%%% @end
%%% Created : 29 Jun 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_conn).

-export([connect/4]).
-export([listen/2]).
-export([accept/2]).
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
  ?DBG("Trying to connect to ~p on ~p~n", [Address, Port]),
  
  {ok, Socket} = quic_prim:connect(Address, Port, Opts, Timeout),
  ?DBG("Socket opened.~n", []),
  
  {ok, Socket}.


-spec listen(Port, Opts) -> Result when
    Port :: inet:port_number(),
    Opts :: [Opt],
    Opt :: gen_quic:option(),
    Result :: {ok, Socket} | {error, Reason},
    Socket :: gen_quic:socket(),
    Reason :: inet:posix().

listen(Port, Opts) ->
  case inet_quic_util:is_opt(Opts, buffer_accept) of
    true ->
      ?DBG("Calling quic_server:listen", []),
      quic_server:listen(Port, Opts);

    false ->
      ?DBG("Listening on port: ~p~n", [Port]),
      
      {ok, Socket} = quic_server:open(Port, Opts),
      ?DBG("Server socket opened~n", []),

      {ok, Socket}
  end.


-spec accept(LSocket, Timeout) -> Result when
    LSocket :: gen_quic:socket(),
    Timeout :: non_neg_integer(),
    Result :: {ok, Socket} | {error, Reason},
    Socket :: gen_quic:socket(),
    Reason :: inet:posix() | timeout.

%% Check to see if the socket is a registered gen_server by the buffer_accept option.
%% If yes it checks the gen_server, otherwise it bypasses it and waits for a valid request.
accept(LSocket, Timeout) ->
  case quic_registry:whereis_name(LSocket) of
    undefined ->
      quic_server:immediate_accept(LSocket, Timeout);

    Pid when is_pid(Pid) ->
      quic_server:accept(LSocket, Timeout)
  end.


%% Opens a new stream on the given Socket.
-spec open(Socket, Opts) -> Result when
    Socket :: gen_quic:socket(),
    Opts :: [Opt],
    Opt :: gen_quic:socket_option(),
    Result :: {ok, StreamID} | {error, Reason},
    StreamID :: {Socket, non_neg_integer()},
    Reason :: gen_quic:errors().

open(Socket, Opts) ->
  quic_stream:open(Socket, Opts).


-spec send(Socket, Message) -> ok when
    Socket :: gen_quic:socket(),
    Message :: binary().

send(Socket, Message) when is_tuple(Socket) ->
  quic_stream:send(Socket, Message);

send(Socket, Message) ->
  quic_prim:send(Socket, Message).


%% Packet Length is ignored since it is a datagram.
-spec recv(Socket, Length, Timeout) -> Result when
    Socket :: gen_quic:socket(),
    Length :: non_neg_integer(),
    Timeout :: non_neg_integer() | infinity,
    Result :: {ok, Data} | {error, Reason},
    Data :: list() | binary(),
    Reason :: inet:posix() | timeout.

recv(Socket, _Length, Timeout) when is_tuple(Socket) ->
  quic_stream:recv(Socket, Timeout);

recv(Socket, _Length, Timeout) ->
  quic_prim:recv(Socket, Timeout).


-spec controlling_process(Socket, Pid) -> Result when
    Socket :: gen_quic:socket(),
    Pid :: pid(),
    Result :: ok | {error, Reason},
    Reason :: closed | not_owner | badarg | inet:posix().

controlling_process(Socket, Pid) when is_tuple(Socket) ->
  quic_stream:controlling_process(Socket, Pid);

controlling_process(Socket, Pid) ->
  quic_prim:controlling_process(Socket, Pid).


-spec close(Socket) -> ok when
    Socket :: gen_quic:socket().

close(Socket) when is_tuple(Socket) ->
  quic_stream:close(Socket);

close(Socket) ->
  quic_prim:close(Socket).


