%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%% Creates streams and encodes stream frames. Keeps track of the 
%%% info used by the stream like offset and stream_id.
%%% Receives parsed stream data and ensures it is in the 
%%% correct order.
%%% @end
%%% Created : 29 Jun 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_stream).

-behaviour(gen_server).

-export([open/2]).
-export([send/2]).
-export([recv/2]).
-export([controlling_process/2]).
-export([close/1]).

-include("quic_headers.hrl").

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3, format_status/2]).

%%%===================================================================
%%% API
%%%===================================================================

%% Opens a new stream on the connection if allowed.
%% The new stream is a gen_server that keeps track of the
%% stream offset and other fields. The gen_server is registered
%% under a tuple of {socket, stream_id} where stream_id
%% is assigned by the main stream0 process (quic_prim).
-spec open(Socket, Opts) -> Result when
    Socket :: gen_quic:socket(),
    Opts :: [Opt],
    Opt :: gen_quic:stream_option(),
    Result :: {ok, Stream} | {error, Reason},
    Stream :: gen_quic:socket(),
    Reason :: gen_quic:errors().

open(Socket, Opts) ->
  {ok, Stream_Opts} = quic_util:parse_stream_opts(Opts),

  case quic_prim:new_stream_id(via(Socket), stream_id) of
    {ok, Stream_ID} ->
      Stream = {Socket, Stream_ID},
      {ok, _Pid} = gen_server:start_link(via(Stream),
                                         ?MODULE,
                                         [Stream, Stream_Opts],
                                         []),
      {ok, Stream};
    
    Error ->
      ?DBG("Error Opening stream: ~p~n", [Error]),
      Error
  end.


-spec send(Socket, Message) -> Result when
    Socket :: gen_quic:socket(),
    Message :: binary(),
    Result :: ok.

send(Socket, Data) ->
  gen_server:call(via(Socket), {send, Data}).


-spec recv(Socket, Timeout) -> Result when
    Socket :: gen_quic:socket(),
    Timeout :: non_neg_integer(),
    Result :: {ok, Message} | {error, Reason},
    Message :: binary() | list(),
    Reason :: gen_quic:errors().

recv(Socket, Timeout) ->
  gen_server:call(via(Socket), recv, Timeout).


-spec controlling_process(Socket, Pid) -> Result when
    Socket :: gen_quic:socket(),
    Pid :: pid(),
    Result :: ok | {error, Reason},
    Reason :: gen_quic:errors().

controlling_process(Socket, Pid) ->
  gen_server:call(via(Socket), {new_owner, Pid}).


-spec close(Socket) -> ok when
    Socket :: gen_quic:socket().

close(Socket) ->
  gen_server:stop(via(Socket), normal, infinity).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

-spec init(Args :: term()) -> {ok, State :: term()} |
                              {ok, State :: term(), Timeout :: timeout()} |
                              {ok, State :: term(), hibernate} |
                              {stop, Reason :: term()} |
                              ignore.

init([{Socket, Stream_ID},
      #quic_stream_opts{} = Stream_Opts]) ->
  process_flag(trap_exit, true),
  {ok, #quic_stream{stream_id = Stream_ID, options = Stream_Opts}}.


-spec handle_call(Request :: term(), From :: {pid(), term()}, State :: term()) ->
                     {reply, Reply :: term(), NewState :: term()} |
                     {reply, Reply :: term(), NewState :: term(), Timeout :: timeout()} |
                     {reply, Reply :: term(), NewState :: term(), hibernate} |
                     {noreply, NewState :: term()} |
                     {noreply, NewState :: term(), Timeout :: timeout()} |
                     {noreply, NewState :: term(), hibernate} |
                     {stop, Reason :: term(), Reply :: term(), NewState :: term()} |
                     {stop, Reason :: term(), NewState :: term()}.

%% TODO: Add max_stream_data frame check.
%% Encoding and sending data.
handle_call({send, Data}, _From,
            #quic_stream{
               socket = Socket
              }=Conn) ->

  {ok, Packet} = quic_packet:encode_frames(Data, Conn),

  quic_prim:send(Socket, Packet),
  {reply, Reply, Conn};

%% TODO: Change to have gen_server store processed packets.
%% Recv
handle_call(recv, _From, Conn) ->
  {reply, Packet, Conn};

%% Changing controlling process.
handle_call({new_owner, Pid}, From, 
            #quic_stream{owner = From}=Conn) ->
  New_Conn = Conn#quic_conn{owner = Pid},
  {reply, ok, New_Conn};

handle_call({new_owner, Pid}, From, Conn) ->
  {reply, {error, not_owner}, Conn};


handle_call(_Request, _From, State) ->
  Reply = ok,
  {reply, Reply, State}.


-spec handle_cast(Request :: term(), State :: term()) ->
                     {noreply, NewState :: term()} |
                     {noreply, NewState :: term(), Timeout :: timeout()} |
                     {noreply, NewState :: term(), hibernate} |
                     {stop, Reason :: term(), NewState :: term()}.

handle_cast(_Request, State) ->
  {noreply, State}.


-spec handle_info(Info :: timeout() | term(), State :: term()) ->
                     {noreply, NewState :: term()} |
                     {noreply, NewState :: term(), Timeout :: timeout()} |
                     {noreply, NewState :: term(), hibernate} |
                     {stop, Reason :: normal | term(), NewState :: term()}.

handle_info(_Info, State) ->
  {noreply, State}.


-spec terminate(Reason :: normal | shutdown | {shutdown, term()} | term(),
                State :: term()) -> any().

terminate(normal, #quic_conn{socket=Socket,
                             src_conn_id=Src_Conn_ID,
                             stream_ID=Stream_ID}) ->
  quic_prim:close({Socket, Src_Conn_ID, Stream_ID});

terminate(_Other, _State) ->
  ok.



-spec code_change(OldVsn :: term() | {down, term()},
                  State :: term(),
                  Extra :: term()) -> {ok, NewState :: term()} |
                                      {error, Reason :: term()}.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.


-spec format_status(Opt :: normal | terminate,
                    Status :: list()) -> Status :: term().

format_status(_Opt, Status) ->
  Status.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec via(Socket) -> Result when
    Socket :: gen_quic:socket(),
    Result :: {via, quic_registry, Socket}.

via(Socket) ->
  {via, quic_registry, Socket}.
