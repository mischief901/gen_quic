%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%%
%%% @end
%%% Created : 14 Nov 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(stream_balancer).

-behaviour(gen_server).

%% API
-export([start_balancer/2]).
-export([open_stream/2, open_stream/3]).
-export([close_stream/1]).
-export([setopts/2]).
-export([getopts/2]).

-include("quic_headers.hrl").

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3, format_status/2]).


%%%===================================================================
%%% API
%%%===================================================================

-spec start_balancer(Socket, Options) -> Result when
    Socket :: gen_quic:socket(),
    Options :: Balancer_Options,
    Balancer_Options :: gen_quic:balancer_option(),
    Result :: {ok, Pid} |
              {error, Reason},
    Pid :: pid(),
    Reason :: gen_quic:error().

start_balancer(Socket, Options) ->
  gen_server:start_link(via({Socket, balancer}), ?MODULE, [Options], []).


-spec open_stream(Socket, Options) -> Result when
    Socket :: gen_quic:socket(),
    Options :: [Option],
    Option :: gen_quic:stream_option(),
    Result :: {ok, {Socket, Stream_ID}} |
              {error, Reason},
    Stream_ID :: non_neg_integer(),
    Reason :: max_stream_blocked_bidi |
              max_stream_blocked_uni.
%% This is called when the local application wants to open a new stream.
%% If the local application tries opening more than the maximum streams allowed,
%% the connection is not closed, but the application is notified and no streams are opened.
open_stream(Socket, Options) ->
  case gen_server:call(via({Socket, balancer}), {open_stream, Socket, Options}) of
    {ok, Stream_ID} ->
      {ok, {Socket, Stream_ID}};
    {error, Reason} ->
      {error, Reason}
  end.

-spec open_stream({Socket, Stream_ID}, Owner, Init_Data) -> Result when
    Socket :: gen_quic:socket(),
    Stream_ID :: non_neg_integer(),
    Owner :: pid(),
    Init_Data :: quic_frame(),
    Result :: ok |
              {error, Reason},
    Reason :: max_stream_blocked_bidi |
              max_stream_blocked_uni.
%% This is called when the peer application wants to open a new stream.
%% The Owner of the socket is notified that a new stream is opened if it is
%% valid, otherwise the connection must be closed and an error frame sent 
%% back to the peer.
open_stream({Socket, Stream_ID}, Owner, Data) ->
  case gen_server:call(via({Socket, balancer}), {open_peer_stream, Stream_ID, Data}) of
    {error, Reason} ->
      {error, Reason};
    {ok, _Pid} ->
      Owner ! {stream_open, {Socket, Stream_ID}},
      ok
  end.


-spec close_stream({Socket, Stream_ID}) -> ok when
    Socket :: gen_quic:socket(),
    Stream_ID :: non_neg_integer().

close_stream({Socket, Stream_ID}) ->
  gen_server:cast(via({Socket, balancer}), {close_stream, Stream_ID}).


-spec setopts(Socket, Options) -> Result when
    Socket :: {gen_quic:socket(), non_neg_integer()} |
              {gen_quic:socket(), balancer},
    Options :: [Option],
    Option :: gen_quic:balancer_option(),
    Result :: ok | {error, Reason},
    Reason :: gen_quic:error().

setopts({_Socket, balancer} = Balancer, Options) ->
  gen_server:call(via(Balancer), {setopts_balancer, Options}).


-spec getopts(Socket, Options) -> Result when
    Socket :: {gen_quic:socket(), balancer},
    Options :: [Option],
    Option :: gen_quic:balancer_option(),
    Result :: ok | {error, Reason},
    Reason :: gen_quic:error().

getopts({_Socket, balancer} = Balancer, Options) ->
  gen_server:call(via(Balancer), {getopts_balancer, Options}).


%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([Balancer_Opts]) ->
  Balancer_Type = maps:get(balancer, Balancer_Opts, none),
  Bidi_Init_ID = maps:get(init_stream_id_bidi, Balancer_Opts, 0),
  Max_Stream_ID_Bidi = maps:get(max_stream_id_bidi, Balancer_Opts, infinity),
  Bidi_Incr = maps:get(stream_id_incr_bidi, Balancer_Opts, 1),
  Uni_Init_ID = maps:get(init_stream_id_uni, Balancer_Opts, 0),
  Max_Stream_ID_Uni = maps:get(max_stream_id_uni, Balancer_Opts, infinity),
  Uni_Incr = maps:get(stream_id_incr_uni, Balancer_Opts, 1),
  Default_Stream_Options = maps:get(default_stream_opts, Balancer_Opts, #{}),
  case Balancer_Type of
    none ->
      {ok, #{type => Balancer_Type,
             uni => {Uni_Init_ID, Uni_Incr, Max_Stream_ID_Uni},
             bidi => {Bidi_Init_ID, Bidi_Incr, Max_Stream_ID_Bidi},
             stream_pids => undefined,
             balancer_opts => Balancer_Opts,
             default_options => Default_Stream_Options
            }
      };
    {custom, Module} ->
      {ok, #{type => Balancer_Type,
             uni => {Uni_Init_ID, Uni_Incr, Max_Stream_ID_Uni},
             bidi => {Bidi_Init_ID, Bidi_Incr, Max_Stream_ID_Bidi},
             stream_pids => Module:init(),
             balancer_opts => Balancer_Opts,
             default_options => Default_Stream_Options
            }
      };
    {max_proc, Max_Stream_Per_Proc} ->
      %% explained below
      {ok, #{type => Balancer_Type,
             uni => {Uni_Init_ID, Uni_Incr, Max_Stream_ID_Uni},
             bidi => {Bidi_Init_ID, Bidi_Incr, Max_Stream_ID_Bidi},
             stream_pids => {Max_Stream_Per_Proc,
                             (Max_Stream_Per_Proc div 2 + 1), 
                             {0, [], #{}, #{}}},
             balancer_opts => Balancer_Opts,
             default_options => Default_Stream_Options
            }
      }
  end.
%% Stores LastID, Increment and max count for uni and bidi streams.

%% Max_Proc explanation:
%% The tuple consists of 3 fields. The first is the maximum number of streams for which a
%% quic_stream gen_server is responsible. The second is the threshold at which procs are
%% requeued and available to accept new streams. (Max div 2 + 1), ensures that all procs
%% are at least half the maximum, or at worst 2 * Optimal or O(2 * n/k) where n is the
%% number of streams and k is the maximum number of streams per process.
%% The third field is a 4-tuple. The first field is the total number of open procs. This
%% is used when rebalancing. The second is a list of all procs with available space.
%% When adding a stream to the proc, the head of the list is added to until full.
%% At which point it is removed and the next one tried. The set of maps in the third and
%% fourth fields map #{Stream_ID => Pid} and #{Pid => Count}. When a Stream is added, 
%% it is added to the first map and the Count corresponding to the Pid in the second is 
%% incremented. When a Stream_ID is removed, it is removed from the first map and the 
%% Count is decremented. If the Pid's corresponding Count is below the threshold, it is 
%% added back onto the list. 
%% Rebalancing has not been worked out completely yet, but the process would occur when 
%% the total number of processes available to accept streams is greater than half the
%% total streams. Probably something as simple as checking the length and not adding it
%% back to the list. Shutting down a stream gen_server will be similar, but only once all
%% streams associated with the server are closed.

%% This may be overkill, but it is pretty easy to program. It is similar to an extensible
%% Array that doubles when full and halves when less than 1/3 full.
%% Defaults to none, an unlimited number of streams per process. (only one process 
%% for all streams of the conn).

%% Custom modules are allowed in which case the following functions must be defined...

handle_call({open_stream, _Socket, #{type := bidi}}, _Owner,
            #{bidi := {Stream_ID, _Incr, Max_ID}} = State) when Stream_ID > Max_ID ->
  {reply, {error, max_stream_id_bidi}, State};

handle_call({open_stream, _Socket, #{type := uni}}, _Owner,
            #{uni := {Stream_ID, _Incr, Max_ID}} = State) when Stream_ID > Max_ID ->
  {reply, {error, max_stream_id_uni}, State};

handle_call({open_stream, Socket, #{type := bidi} = Options}, Owner,
            #{type := Type,
              bidi := {Stream_ID, Incr, Max_ID},
              stream_pids := Stream_Pids0,
              default_stream_options := Default_Options
             } = State) ->
  case get_proc(Type, Stream_Pids0) of
    {ok, Pid, Stream_Pids1} ->
      quic_stream:add_stream(Pid, Owner, Stream_ID, Options),
      {reply, {ok, {Socket, Stream_ID}}, State#{bidi := {Stream_ID + Incr, Incr, Max_ID},
                                                stream_pids := Stream_Pids1}};
    {error, empty} ->
      {ok, Pid} = quic_stream:open_stream(Socket, Default_Options),
      quic_stream:add_stream(Pid, Owner, Stream_ID, Options),
      {ok, Stream_Pids1} = add_proc(Type, Stream_Pids0, Pid),
      {reply, {ok, {Socket, Stream_ID}}, State#{bidi := {Stream_ID + Incr, Incr, Max_ID},
                                                stream_pids := Stream_Pids1}}
  end;

handle_call({open_stream, Socket, #{type := uni} = Options}, Owner,
            #{type := Type,
              uni := {Stream_ID, Incr, Max_ID},
              stream_pids := Stream_Pids0,
              default_stream_options := Default_Options
             } = State) ->
  case get_proc(Type, Stream_Pids0) of
    {ok, Pid, Stream_Pids1} ->
      quic_stream:add_stream(Pid, Owner, Stream_ID, Options),
      {reply, {ok, {Socket, Stream_ID}}, State#{uni := {Stream_ID + Incr, Incr, Max_ID},
                                                stream_pids := Stream_Pids1}};
    {error, empty} ->
      {ok, Pid} = quic_stream:open_stream(Socket, Default_Options),
      quic_stream:add_stream(Pid, Owner, Stream_ID, Options),
      {ok, Stream_Pids1} = add_proc(Type, Stream_Pids0, Pid),
      {reply, {ok, {Socket, Stream_ID}}, State#{uni := {Stream_ID + Incr, Incr, Max_ID},
                                                stream_pids := Stream_Pids1}}
  end;

handle_call({open_peer_stream, _Socket, Stream_ID, #{type := bidi}}, _, 
            #{bidi := {_, _, Max_ID}} = State) when Stream_ID > Max_ID ->
  {reply, {error, max_stream_blocked_bidi}, State};

handle_call({open_peer_stream, _Socket, Stream_ID, #{type := uni}}, _,
            #{uni := {_, _, Max_ID}} = State) when Stream_ID > Max_ID ->
  {reply, {error, max_stream_blocked_uni}, State};

handle_call({open_peer_stream, Socket, Stream_ID, #{type := bidi} = Frame}, _,
            #{type := Type,
              bidi := {Next_ID, Incr, Max_ID},
              stream_pids := Stream_Pids0,
              default_stream_options := Default_Options
             } = State) ->
  case get_proc(Type, Stream_Pids0) of
    {ok, Pid, Stream_Pids1} when Next_ID =< Stream_ID ->
      %% This sets the next stream_ID that the local side can open to be larger than the
      %% largest previously opened stream.
      quic_stream:add_peer_stream(Pid, Stream_ID, Frame),
      {reply, {ok, {Socket, Stream_ID}}, State#{bidi := {Stream_ID + Incr, Incr, Max_ID},
                                                stream_pids := Stream_Pids1}};

    {ok, Pid, Stream_Pids1} ->
      %% If the new Stream_ID is less than the Next_ID, the stream is still opened, but
      %% the max id is not incremented. I think this is adherent to the specs.
      quic_stream:add_peer_stream(Pid, Stream_ID, Frame),
      {reply, {ok, {Socket, Stream_ID}}, State#{stream_pids := Stream_Pids1}};
    
    {error, empty} ->
      {ok, Pid} = quic_stream:open_stream(Socket, Default_Options),
      quic_stream:add_peer_stream(Pid, Stream_ID, Frame),
      {ok, Stream_Pids1} = add_proc(Type, Stream_Pids0, Pid),
      {reply, {ok, {Socket, Stream_ID}}, State#{bidi := {Stream_ID + Incr, Incr, Max_ID},
                                                stream_pids := Stream_Pids1}}
  end;

handle_call({open_stream_peer, Socket, Stream_ID, #{type := uni} = Frame}, _,
            #{type := Type,
              uni := {Next_ID, Incr, Max_ID},
              stream_pids := Stream_Pids0,
              default_stream_options := Default_Options
             } = State) ->
  case get_proc(Type, Stream_Pids0) of
    {ok, Pid, Stream_Pids1} when Next_ID =< Stream_ID ->
      %% This sets the next stream_ID that the local side can open to be larger than the
      %% largest previously opened stream.
      quic_stream:add_peer_stream(Pid, Stream_ID, Frame),
      {reply, {ok, {Socket, Stream_ID}}, State#{uni := {Stream_ID + Incr, Incr, Max_ID},
                                                stream_pids := Stream_Pids1}};

    {ok, Pid, Stream_Pids1} ->
      %% If the new Stream_ID is less than the Next_ID, the stream is still opened, but
      %% the max id is not incremented. I think this is adherent to the specs.
      quic_stream:add_peer_stream(Pid, Stream_ID, Frame),
      {reply, {ok, {Socket, Stream_ID}}, State#{stream_pids := Stream_Pids1}};

    {error, empty} ->
      {ok, Pid} = quic_stream:open_stream(Socket, Default_Options),
      quic_stream:add_peer_stream(Pid, Stream_ID, Frame),
      {ok, Stream_Pids1} = add_proc(Type, Stream_Pids0, Pid),
      {reply, {ok, {Socket, Stream_ID}}, State#{uni := {Stream_ID + Incr, Incr, Max_ID},
                                                stream_pids := Stream_Pids1}}
  end;

handle_call(_Request, _From, State) ->
  Reply = ok,
  {reply, Reply, State}.


handle_cast({close_stream, Stream_ID},
            #{type := Type,
              stream_pids := Stream_Pids0} = State) ->
  {ok, Stream_Pids1} = remove_proc(Type, Stream_Pids0, Stream_ID),
  {noreply, State#{stream_pids := Stream_Pids1}};

handle_cast(_Request, State) ->
  {noreply, State}.


handle_info(_Info, State) ->
  {noreply, State}.


terminate(_Reason, _State) ->
  ok.


code_change(_OldVsn, State, _Extra) ->
  {ok, State}.


format_status(_Opt, Status) ->
  Status.

%%%===================================================================
%%% Internal functions
%%%===================================================================


-spec get_proc(none, Pid) -> Result when
    Pid :: pid() | undefined,
    Result :: {ok, Pid, Pid} | {error, empty};
              ({max_proc, Max_Stream}, Stream_Pids) -> Result when
    Max_Stream :: non_neg_integer(),
    Stream_Pids :: {Max_Stream, Low_Stream, Map},
    Low_Stream :: non_neg_integer(),
    Map :: {Count, Ready, Stream_Pid_Map, Pid_Count_Map},
    Count :: non_neg_integer(),
    Ready :: [pid()],
    Stream_Pid_Map :: #{Stream_ID => pid()},
    Pid_Count_Map :: #{pid() => Count},
    Stream_ID :: non_neg_integer(),
    Result :: {error, empty} | {ok, pid(), Map};
              ({custom, Module}, Custom_Structure) -> Result when
    Module :: atom(),
    Custom_Structure :: any(),
    Result :: {error, empty} | {ok, pid(), Custom_Structure}.
%% The none cases are relatively easy.
get_proc(none, undefined) ->
  {error, empty};
get_proc(none, Stream_Pids) ->
  {ok, Stream_Pids, Stream_Pids};

get_proc({max_proc, _}, {_, _, {_, [], _, _}}) ->
  {error, empty};

get_proc({max_proc, _}, {Max, Min, {Count, [Ready | Rest] = All, Streams, Pid_Map}}) ->
  case maps:get(Ready, Pid_Map) of
    Count when Count + 1 >= Max ->
      %% Remove the Pid from the ready list and update count.
      {ok, Ready, {Max, Min, {Count, Rest, Streams, maps:put(Ready, Count + 1, Pid_Map)}}};
    Count ->
      %% Otherwise keep it in the ready list and update count.
      {ok, Ready, {Max, Min, {Count, All, Streams, maps:put(Ready, Count + 1, Pid_Map)}}}
  end.


-spec add_proc(none, undefined, pid()) -> {ok, pid()};
              ({max_proc, Max_Procs}, Stream_Pids, Pid) -> {ok, Stream_Pids} when
    Max_Procs :: non_neg_integer(),
    Pid :: pid(),
    Stream_Pids :: {Max_Procs, Low_Stream, Map},
    Low_Stream :: non_neg_integer(),
    Map :: {Count, Ready, Stream_Pid_Map, Pid_Count_Map},
    Count :: non_neg_integer(),
    Ready :: [Pid],
    Stream_Pid_Map :: #{Stream_ID => Pid},
    Pid_Count_Map :: #{Pid => Count},
    Stream_ID :: non_neg_integer();
              ({custom, Module}, Custom_Structure, Pid) -> {ok, Custom_Structure} when
    Module :: atom(),
    Custom_Structure :: any(),
    Pid :: pid().

add_proc(none, undefined, Pid) -> {ok, Pid};

add_proc({max_proc, _}, {Max, Min, {Count, Ready, Streams, Pids}}, Pid) -> 
  {ok, {Max, Min, {Count + 1, [Pid | Ready], Streams, Pids#{Pid => 0}}}}.


-spec remove_proc(none, Pid, Stream_ID) -> {ok, Pid} when
    Pid :: pid(),
    Stream_ID :: non_neg_integer();
                 ({max_proc, Max_Procs}, Stream_Pids, Stream_ID) -> {ok, Stream_Pids} when
    Max_Procs :: non_neg_integer(),
    Pid :: pid(),
    Stream_Pids :: {Max_Procs, Low_Stream, Map},
    Low_Stream :: non_neg_integer(),
    Map :: {Count, Ready, Stream_Pid_Map, Pid_Count_Map},
    Count :: non_neg_integer(),
    Ready :: [Pid],
    Stream_Pid_Map :: #{Stream_ID => Pid},
    Pid_Count_Map :: #{Pid => Count},
    Stream_ID :: non_neg_integer();
                 ({custom, Module}, Custom_Structure, Stream_ID) -> {ok, Custom_Structure} when
    Module :: atom(),
    Custom_Structure :: any(),
    Stream_ID :: non_neg_integer().

%% The none will not change anything.
remove_proc(none, Pid, _) -> {ok, Pid};
remove_proc({max_proc, _}, 
            {Max, Min, {Pid_Count, Ready, Stream_Pid_Map0, Pid_Count_Map0}}, 
            Stream_ID) ->
  %% Remove the stream_id from the map.
  {Pid, Stream_Pid_Map1} = maps:take(Stream_ID, Stream_Pid_Map0),
  
  case maps:get(Pid, Pid_Count_Map0) of
    Count when Count =< Min ->
      %% If the pid has a count below the minimum threshold, add it to the ready list.
      Pid_Count_Map1 = maps:put(Pid, Count - 1, Pid_Count_Map0),
      {ok, {Max, Min, {Pid_Count, [Pid | Ready], Stream_Pid_Map1, Pid_Count_Map1}}};
    Count ->
      %% Otherwise just update the count.
      Pid_Count_Map1 = maps:put(Pid, Count - 1, Pid_Count_Map0),
      {ok, {Max, Min, {Pid_Count, Ready, Stream_Pid_Map1, Pid_Count_Map1}}}
  end.


via(Socket) -> {via, quic_registry, Socket}.
