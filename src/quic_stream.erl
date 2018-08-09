%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%% quic_stream is a callback module to support stream based communication
%%% on a quic connections.
%%% This is a callback module. See quic_conn for the API.
%%% @end
%%% Created : 29 Jun 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_stream).

-behaviour(gen_server).

-include("quic_headers.hrl").

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3, format_status/2]).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([Owner, Socket, Stream_ID, Limits, Stream_Opts]) ->
  process_flag(trap_exit, true),
  
  %% Not too many options here yet, but does initialize the state
  %% based on the ones we do have.
  Stream0 = set_opts(#quic_stream{}, Limits), 
  Stream1 = set_opts(Stream0, Stream_Opts),
  
  {ok, Stream1#quic_stream{
         owner = Owner,
         socket = Socket,
         stream_id = Stream_ID
        }}.

handle_call(recv, _From, Stream) ->
  {reply, ok, Stream};

%% Changing controlling process.
handle_call({new_owner, Pid}, From,
            #quic_stream{owner = From} = Stream) ->
  {reply, ok, Stream#quic_stream{owner = Pid}};

handle_call({new_owner, _Pid}, _From, Stream) ->
  {reply, {error, not_owner}, Stream};

handle_call(_Request, _From, State) ->
  Reply = ok,
  {reply, Reply, State}.

%% TODO: Add max_stream_data frame check.
%% Encoding and sending data.
handle_cast({send, Raw_Data},
            #quic_stream{
               socket = Socket,
               socket_pid = Pid,
               offset = Offset,
               pack_type = Pack_Type,
               max_data = Max
              } = Stream) when byte_size(Raw_Data) + Offset =< Max->
  %% We have room to send the frames on the stream.
  %% TODO: Update encode_frame to take in and return quic_stream.
  {ok, Frame, Stream} = quic_packet:encode_frame(Raw_Data, Stream0),

  gen_statem:cast(Pid, {send, {Pack_Type, Frame}}),

  {noreply, Stream};

handle_cast({send, Raw_Data},
            #quic_stream{
               socket = Socket,
               offset = Offset
              } = Stream) ->
  %% The maximum data of the stream has been reached. Send a message indicating
  %% we want more room and add Raw_Data to buffer.
  %% TODO:
  ok;

handle_cast(_Request, State) ->
  {noreply, State}.


%% TODO: This will need to handle messages like {stream_data, Frame} from the
%% state machine processes.
%% Will need to respond accordingly if stream limits are violated.
%% Also handle updates to stream limits.
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
    Socket :: gen_quic:socket(),
    Result :: {via, quic_registry, Socket}.

via(Socket) ->
  {via, quic_registry, Socket}.


set_opts(Stream, Opts) ->
  %% TODO:
  #quic_stream{}.


