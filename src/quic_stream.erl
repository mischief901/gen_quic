%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%% @end
%%%-------------------------------------------------------------------
-module(quic_stream).

-behaviour(gen_server).

-include("quic_headers.hrl").

-export([open_stream/3]).
-export([add_stream/4]).
-export([add_peer_stream/3]).
-export([send/2]).
-export([recv/2]).
-export([close/1]).
-export([shutdown/1]).
-export([controlling_process/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3, format_status/2]).

-spec open_stream(Socket, Version, Default_Options) -> Result when
    Socket :: gen_quic:socket(),
    Version :: binary() | atom(),
    Default_Options :: map(),
    Result :: {ok, Pid},
    Pid :: pid().

open_stream(Socket, Version, Default_Options) ->
  gen_server:start_link(?MODULE, [Socket, Version, Default_Options], []).


-spec add_stream(Pid, Owner, Stream_ID, Options) -> Result when
    Pid :: pid(),
    Owner :: pid(),
    Stream_ID :: non_neg_integer(),
    Options :: map(),
    Result :: ok.

add_stream(Pid, Owner, Stream_ID, Options) ->
  gen_server:cast(Pid, {add_stream, Owner, Stream_ID, Options}).


-spec add_peer_stream(Pid, Stream_ID, Initial_Frame) -> ok when
    Pid :: pid(),
    Stream_ID :: non_neg_integer(),
    Initial_Frame :: map().

add_peer_stream(Pid, Stream_ID, Init_Frame) ->
  gen_server:cast(Pid, {add_peer_stream, Stream_ID, Init_Frame}).


-spec send(Stream, Data) -> Result when
    Stream :: gen_quic:stream(),
    Data :: binary() | list(),
    Result :: ok.

send({Socket, Stream_ID} = Stream, Data) when is_list(Data) ->
  send(Stream, list_to_binary(Data));

send({Socket, Stream_ID} = Stream, Data) ->
  gen_server:cast(via(Stream), {send, Stream_ID, Data}).


-spec recv(Stream, Timeout) -> Result when
    Stream :: gen_quic:stream(),
    Timeout :: non_neg_integer() | infinity,
    Result :: {ok, Data} | {error, timeout},
    Data :: binary() | list().

recv({_Socket, Stream_ID} = Stream, Timeout) ->
  recv(Stream, Timeout, 0).

recv(Stream, Timeout, Current) when Current >= Timeout ->
  {error, timeout};
recv({Socket, Stream_ID} = Stream, Timeout, Current) ->
  case gen_server:call(via(Stream), {recv, Stream_ID}, 100) of
    {error, timeout} ->
      recv(Stream, Timeout, Current + 100);
    Other ->
      Other
  end.

-spec controlling_process(Stream, Pid) -> ok | {error, not_owner} when
    Stream :: gen_quic:stream(),
    Pid :: pid().

controlling_process({_Socket, Stream_ID} = Stream, Pid) ->
  gen_server:call(via(Stream), {new_owner, Stream_ID, Pid}).


-spec close(Stream) -> ok | {error, not_owner} | {error, not_found} when
    Stream :: gen_quic:stream().

close({_Socket, Stream_ID} = Stream) ->
  case gen_server:call(via(Stream), {close, Stream_ID}) of
    ok ->
      stream_balancer:close_stream(Stream);

    {error, _Reason} = Error ->
      Error
  end.


-spec shutdown(Pid :: pid()) -> ok | {error, stream_open}.

shutdown(Pid) ->
  gen_server:call(Pid, shutdown).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([Socket, Version, Default_Options]) ->
  process_flag(trap_exit, true),

  {ok, #{socket => Socket,
         version => Version,
         stream_ids => #{},
         default_options => Default_Options}}.


handle_call(recv, _From, Stream) ->
  {reply, ok, Stream};

%% Changing controlling process.
handle_call({controlling_process, Stream_ID, Pid}, From,
            #{stream_ids := Stream0} = State) ->
  case maps:get(Stream_ID, Stream0, not_found) of
    not_found ->
      {reply, {error, not_found}, State};

    #{owner := From} = Stream_Data0 ->
      Stream_Data = Stream_Data0#{owner := Pid},
      {reply, ok, State#{stream_ids := Stream0#{Stream_ID := Stream_Data}}};

    _ ->
      {reply, {error, not_owner}, State}
  end;

handle_call(_Request, _From, State) ->
  Reply = ok,
  {reply, Reply, State}.


handle_cast({add_stream, Owner, Stream_ID, Options},
            #{socket := Socket,
              version := Version,
              stream_ids := Stream0} = State) ->
  Stream_Type = maps:get(type, Options),
  Stream1 = maps:put(Stream_ID, #{owner => Owner,
                                  type => {local, Stream_Type},
                                  options => Options,
                                  buffer => [],
                                  recv_offset => 0,
                                  send_offset => 0},
                     Stream0),
  Pack_Type = maps:get(pack, Options, none),
  Frame0 = #{type => stream_open,
             stream_id => Stream_ID},
  {ok, Frame} = quic_packet:form_frame(Version, Frame0),
  quic_conn:send(Socket, {Pack_Type, Frame}),
  {noreply, State#{stream_ids := Stream1}};

handle_cast({add_peer_stream, Stream_ID, Init_Frame},
            #{stream_ids := Stream0,
              default_options := Default_Options} = State) ->
  
  Stream_Type = maps:get(type, Init_Frame),
  Stream1 = maps:put(Stream_ID, #{type => {peer, Stream_Type},
                                  options => Default_Options,
                                  buffer => [],
                                  recv_offset => 0,
                                  send_offset => 0},
                     Stream0),
  gen_server:cast(self(), {stream_data, Init_Frame}),
  {noreply, State#{stream_ids := Stream1}};

handle_cast({send, Stream_ID, Raw_Data},
            #{socket := Socket,
              version := Version,
              stream_ids := Stream0
             } = State) ->
  case maps:get(Stream_ID, Stream0, undefined) of
    undefined ->
      {noreply, State};
    
    #{send_offset := Offset,
      options := Options
     } = Stream_Data0 ->
      Frame0 = #{type => stream_data,
                 offset => Offset,
                 stream_id => Stream_ID,
                 binary => Raw_Data},
      Length = byte_size(Raw_Data),
      {ok, Frame} = quic_packet:form_frame(Version, Frame0),
      Pack_Type = maps:get(pack, Options, none),
      quic_conn:send(Socket, {Pack_Type, Frame}),
      Stream_Data = Stream_Data0#{send_offset := Offset + Length},
      Streams = Stream0#{stream_ids := Stream_Data},
      {noreply, State#{stream_ids := Streams}}
  end;

handle_cast(_Request, State) ->
  {noreply, State}.


handle_info(_Info, State) ->
  {noreply, State}.


terminate(_Other, _State) ->
  ok.


code_change(_OldVsn, State, _Extra) ->
  {ok, State}.


format_status(_Opt, Status) ->
  Status.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec via(Socket) -> Result when
    Socket :: gen_quic:socket() | gen_quic:stream() | {gen_quic:socket(), balancer},
    Result :: {via, quic_registry, Socket}.

via(Socket) ->
  {via, quic_registry, Socket}.



