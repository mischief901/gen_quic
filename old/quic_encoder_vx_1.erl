%%%-------------------------------------------------------------------
%%% @author alex
%%% @copyright (C) 2018, alex
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(quic_encoder_vx_1).

%% API
-export([to_frame/1]).
-export([to_app_error/1, to_conn_error/1]).

-include("quic_headers.hrl").
-include("quic_vx_1.hrl").


%%%===================================================================
%%% API
%%%===================================================================

%% These functions are the list of functions to call when a specific type is parsed.
%% This enables the entire packet to be parsed with optimized sub-binary creation
%% and allows for easy changes to the frame headers.
%% The list must be of valid function names. The dispatch function is parse_next.
%% Custom function entries must be added to the parse_next case statement.
%% The last function call should always be parse_frame unless the entire packet is parsed.

%% Padding and Ping just loop back to parse_frame.
padding() -> [parse_frame].
ping() -> [parse_frame].

%% Conn_Close and App_Close read an error, message length, and message.
conn_close() -> [parse_conn_error, parse_message, parse_frame].
app_close() -> [parse_app_error, parse_message, parse_frame].

%% Reset Stream reads a stream_id, app_error, and last stream offset.
rst_stream() -> [parse_var_length, parse_app_error, parse_var_length, parse_frame].

%% Max_Data and Max_Stream_ID read a variable integer, respectively.
max_data() -> [parse_var_length, parse_frame].
max_stream_id() -> [parse_var_length, parse_frame].

%% Max_Stream_Data parses the stream ID and data limit.
max_stream_data() -> [parse_var_length, parse_var_length, parse_frame].

%% Blocked and Stream_ID_Blocked reads the wanted value above limit.
data_blocked() -> [parse_var_length, parse_frame].
stream_id_blocked() -> [parse_var_length, parse_frame].

%% Stream_Data_Blocked reads the stream ID and the blocked value.
stream_data_blocked() -> [parse_var_length, parse_var_length, parse_frame].

%% New_Conn_ID reads a sequence number and a new connection ID with the
%% 128 bit stateless retry token.
new_conn_id() -> [parse_var_length, parse_conn_id, parse_token, parse_frame].

%% Stop_Sending reads a stream id and app error code
stop_sending() -> [parse_var_length, parse_app_error, parse_frame].

%% ack_frame reads the largest ack in the ack block, the ack_delay, and the
%% number of blocks/gaps in the ack_block then parses the ack_block.
ack_frame() -> [parse_var_length, parse_var_length, parse_var_length, parse_ack_blocks, parse_frame].

%% Path_Challenge and Path_Response read the 64 bit random Nonce for
%% the path challenge and response protocol.
path_challenge() -> [parse_challenge, parse_frame].
path_response() -> [parse_challenge, parse_frame].

%% The streams have different headers so the stream event list has 
%% the argument {Offset, Length, Fin} to indicate if the relevant bits are set.
%% New stream with the remainder of the packet being the stream message.

stream({Offset, Length}) -> 
  [parse_var_length] ++ stream_offset(Offset) ++ stream_length(Length).

%% If the offset bit is set, there is a variable length offset in the frame header.
stream_offset(0) -> [];
stream_offset(1) -> [parse_var_length].

%% If the length bit is not set, the remainder of the packet is the message.
%% So no looping back to parse_frame.
stream_length(0) -> [];
stream_length(1) -> [parse_var_length, parse_message, parse_frame].



%% The parse_next function is a dispatch function that calls the next item to
%% parse in the frame header. This is necessary so that the sub-binary
%% optimizations can be utilized. Calling Fun(Packet, ...) is too dynamic for the
%% compiler to allow the optimizations.

parse_next(<<Packet/bits>>, Header, Frames, [Next_Fun | Funs]) ->
  case Next_Fun of
    parse_frame ->
      parse_frame(Packet, Header, Frames);

    parse_var_length ->
      parse_var_length(Packet, Header, Frames, Funs);
    
    parse_conn_error ->
      parse_conn_error(Packet, Header, Frames, Funs);

    parse_app_error ->
      parse_app_error(Packet, Header, Frames, Funs);
    
    parse_message ->
      parse_message(Packet, Header, Frames, Funs);

    parse_ack_blocks ->
      parse_ack_blocks(Packet, Header, Frames, Funs);

    parse_token ->
      parse_token(Packet, Header, Frames, Funs);
    
    parse_conn_id ->
      parse_conn_id(Packet, Header, Frames, Funs)

  end;

parse_next(<<>>, Header, Frames, []) ->
  {ok, Header, Frames};

parse_next(<<>>, _Header, _Frames, Funs) ->
  ?DBG("Error with parsing dispatch functions: ~p~n", [Funs]),
  {error, badarg};

parse_next(Binary, _Header, _Frames, Funs) ->
  ?DBG("Error with parsing dispatch functions: ~p~n", [Binary]),
  ?DBG("Funs: ~p~n", [Funs]),
  {error, badarg}.

%% TODO: Use records instead of tuples.

parse_frames(<<Binary/bits>>, Header_Info) ->
  parse_next(Binary, Header_Info, [], [parse_frame]).

parse_frame(<<0:1, 0:1, 0:1, 0:1, Type:4, Rest/bits>>, H, F) ->
  case Type of
    ?PADDING ->
      ?DBG("Padding.~n", []),
      parse_next(Rest, H, F, padding());

    ?RST_STREAM ->
      ?DBG("Reset Stream.~n", []),
      parse_next(Rest, H, [rst_stream | F], rst_stream());

    ?CONN_CLOSE ->
      ?DBG("Connection Close.~n", []),
      parse_next(Rest, H, [conn_close | F], conn_close());

    ?APP_CLOSE ->
      ?DBG("Application Close.~n", []),
      parse_next(Rest, H, [app_close | F], app_close());

    ?MAX_DATA ->
      ?DBG("Max Data.~n", []),
      parse_next(Rest, H, [max_data | F], max_data());

    ?MAX_STREAM_DATA ->
      ?DBG("Max Stream Data.~n", []),
      parse_next(Rest, H, [max_stream_data | F], max_stream_data());

    ?MAX_STREAM_ID ->
      ?DBG("Max Stream ID.~n", []),
      parse_next(Rest, H, [max_stream_id | F], max_stream_id());

    ?PING ->
      ?DBG("Ping.~n", []),
      parse_next(Rest, H, [ping | F], ping());

    ?BLOCKED ->
      ?DBG("Blocked.~n", []),
      parse_next(Rest, H, [data_blocked | F], data_blocked());

    ?STREAM_BLOCKED ->
      ?DBG("Stream Blocked.~n", []),
      parse_next(Rest, H, [stream_data_blocked | F], stream_data_blocked());

    ?STREAM_ID_BLOCKED ->
      ?DBG("Stream ID Blocked.~n", []),
      parse_next(Rest, H, [stream_id_blocked | F], stream_id_blocked());

    ?NEW_CONN_ID ->
      ?DBG("New Connection ID.~n", []),
      parse_next(Rest, H, [new_conn_id | F], new_conn_id());

    ?STOP_SENDING ->
      ?DBG("Stop Sending.~n", []),
      parse_next(Rest, H, [stop_sending | F], stop_sending());

    ?ACK_FRAME ->
      ?DBG("Ack Frame.~n", []),
      parse_next(Rest, H, [ack_frame | F], ack_frame());

    ?PATH_CHALLENGE ->
      ?DBG("Path Challenge.~n", []),
      parse_next(Rest, H, [path_challenge | F], path_challenge());

    ?PATH_RESPONSE ->
      ?DBG("Path Response.~n", []),
      parse_next(Rest, H, [path_response | F], path_response())

  end;

parse_frame(<<1:4, 0:1, Off:1, Len:1, 0:1 , Rest/bits>>, H, F) ->
  parse_next(Rest, H, [stream_data | F], stream({Off, Len}));

parse_frame(<<1:4, 0:1, Off:1, Len:1, 1:1 , Rest/bits>>, H, F) ->
  parse_next(Rest, H, [stream_end | F], stream({Off, Len}));

parse_frame(Other, H, F) ->
  ?DBG("Not a proper frame type: ~p.~n", [Other]),
  ?DBG("Header: ~p~n", [H]),
  ?DBG("Frames: ~p~n", [F]),
  {error, badarg}.

%% %% Forms a frame for the given type and data.
%% %% Fin bit is not set for stream_data.
%% to_frame({stream_data, {Stream_ID, Offset, Message}}) ->
%%   Length = byte_size(Message),
%%   ID_Bin = to_var_length(Stream_ID),
%%   case {Offset, Length} of
%%     {0, 0} ->
%%       Frame = list_to_bitstring([<<1:5>>, <<0:3>>, ID_Bin]),
%%       {ok, Frame, byte_size(Frame)};

%%     {0, _} ->
%%       Len_Bin = to_var_length(Length),
%%       Frame = list_to_bitstring([<<1:5>>, <<2:3>>, ID_Bin, Len_Bin, Message]),
%%       {ok, Frame, byte_size(Frame)};

%%     {_, 0} ->
%%       %% Can only happen when a stream is closing
%%         ?DBG("Invalid stream specification. Offset: ~p, Length:~p~n",
%%              [Offset, Length]),
%%       {error, badarg};
    
%%     {_, _} ->
%%       Len_Bin = to_var_length(Length),
%%       Off_Bin = to_var_length(Offset),
%%       Frame = list_to_bitstring([<<1:5>>, <<6:3>>, ID_Bin, Off_Bin, Len_Bin, 
%%                                  Message]),
%%       {ok, Frame, byte_size(Frame)}
%%     end;

%% %% Fin bit is set for stream_close.
%% to_frame({stream_close, {Stream_ID, Offset, Message}}) ->
%%   Length = byte_size(Message),
%%   ID_Bin = to_var_length(Stream_ID),
%%   case {Offset, Length} of
%%     {0, 0} ->
%%       Frame = list_to_bitstring([<<1:5>>, <<1:3>>, ID_Bin]),
%%       {ok, Frame, byte_size(Frame)};

%%     {0, _} ->
%%       Len_Bin = to_var_length(Length),
%%       Frame = list_to_bitstring([<<1:5>>, <<3:3>>, ID_Bin, Len_Bin, Message]),
%%       {ok, Frame, byte_size(Frame)};

%%     {_, 0} ->
%%       Off_Bin = to_var_length(Offset),
%%       Frame = list_to_bitstring([<<1:5>>, <<5:3>>, ID_Bin, Off_Bin, Message]),
%%       {ok, Frame, byte_size(Frame)};
    
%%     {_, _} ->
%%       Len_Bin = to_var_length(Length),
%%       Off_Bin = to_var_length(Offset),
%%       Frame = list_to_bitstring([<<1:5>>, <<7:3>>, ID_Bin, Off_Bin, 
%%                                  Len_Bin, Message]),
%%       {ok, Frame, byte_size(Frame)}
%%     end;

%% to_frame(padding) ->
%%   {ok, <<?PADDING:8>>, 1};

%% to_frame({rst_stream, Stream_ID, App_Error, Offset}) ->
%%   ID_Bin = to_var_length(Stream_ID),
%%   Off_Bin = to_var_length(Offset),
%%   Err_Bin = to_app_error(App_Error),
%%   {ok, list_to_bitstring([<<?RST_STREAM:8>>, ID_Bin, Err_Bin, Off_Bin])};

%% to_frame({conn_close, Conn_Error, Reason}) ->
%%   Err_Bin = to_conn_error(Conn_Error),
%%   Len_Bin = to_var_length(byte_size(Reason)),
%%   {ok, list_to_bitstring([<<?CONN_CLOSE:8>>, Err_Bin, Len_Bin, Reason])};

%% to_frame({app_close, App_Error, Reason}) ->
%%   Err_Bin = to_app_error(App_Error),
%%   Len_Bin = to_var_length(byte_size(Reason)),
%%   {ok, list_to_bitstring([<<?APP_CLOSE:8>>, Err_Bin, Len_Bin, Reason])};

%% to_frame({max_data, Max_Data}) ->
%%   Data_Bin = to_var_length(Max_Data),
%%   {ok, list_to_bitstring([<<?MAX_DATA:8>>, Data_Bin])};

%% to_frame({max_stream_data, Stream_ID, Max_Data}) ->
%%   ID_Bin = to_var_length(Stream_ID),
%%   Data_Bin = to_var_length(Max_Data),
%%   {ok, list_to_bitstring([<<?MAX_STREAM_DATA:8>>, ID_Bin, Data_Bin])};

%% to_frame({max_stream_id, Stream_ID}) ->
%%   ID_Bin = to_var_length(Stream_ID),
%%   {ok, list_to_bitstring([<<?MAX_STREAM_ID:8>>, ID_Bin])};

%% to_frame(ping) ->
%%   {ok, <<?PING:8>>};

%% to_frame({blocked, Offset}) ->
%%   Off_Bin = to_var_length(Offset),
%%   {ok, list_to_bitstring([<<?BLOCKED:8>>, Off_Bin])};

%% to_frame({stream_blocked, Stream_ID, Offset}) ->
%%   ID_Bin = to_var_length(Stream_ID),
%%   Off_Bin = to_var_length(Offset),
%%   {ok, list_to_bitstring([<<?STREAM_BLOCKED:8>>, ID_Bin, Off_Bin])};

%% to_frame({stream_id_blocked, Stream_ID}) ->
%%   ID_Bin = to_var_length(Stream_ID),
%%   {ok, list_to_bitstring([<<?STREAM_ID_BLOCKED:8>>, ID_Bin])};

%% to_frame({new_conn_id, Sequence, Length, Conn_ID, Token}) ->
%%   Seq_Bin = to_var_length(Sequence),
%%   {ok, list_to_bitstring([<<?NEW_CONN_ID:8>>, Seq_Bin, <<Length:8>>,
%%                           <<Conn_ID:Length/unit:8>>, <<Token:128>>])};

%% to_frame({stop_sending, Stream_ID, App_Error}) ->
%%   ID_Bin = to_var_length(Stream_ID),
%%   Err_Bin = to_app_error(App_Error),
%%   {ok, list_to_bitstring([<<?STOP_SENDING:8>>, ID_Bin, Err_Bin])};

%% to_frame({ack_frame, Largest, Ack_Delay, Ack_Block_Count, Acks}) ->
%%   Largest_Bin = to_var_length(Largest),
%%   Delay_Bin = to_var_length(Ack_Delay),
%%   Count_Bin = to_var_length(Ack_Block_Count),
%%   Ack_Bin = to_ack_block(Largest, Acks),
%%   {ok, list_to_bitstring([<<?ACK_FRAME:8>>, Largest_Bin, Delay_Bin, 
%%                           Count_Bin, Ack_Bin])};

%% to_frame({path_challenge, Challenge}) ->
%%   {ok, list_to_bitstring([<<?PATH_CHALLENGE:8>>, <<Challenge:64>>])};

%% to_frame({path_response, Challenge}) ->
%%   {ok, list_to_bitstring([<<?PATH_RESPONSE:8>>, <<Challenge:64>>])};

%% to_frame(Other) ->
%%   ?DBG("Invalid frame type ~p~n", [Other]),
%%   {error, badarg}.


  
%%%===================================================================
%%% Internal functions
%%%===================================================================



to_app_error(stopping) ->
  <<?STOPPING:16>>;
to_app_error(Other) ->
  ?DBG("App error not implemented: ~p~n", [Other]).


to_conn_error(ok) ->
  <<?NO_ERROR:16>>;

to_conn_error({error, internal}) ->
  <<?INTERNAL_ERROR:16>>;

to_conn_error({error, server_busy}) ->
  <<?SERVER_BUSY:16>>;

to_conn_error({error, flow_control}) ->
  <<?FLOW_CONTROL_ERROR:16>>;

to_conn_error({error, stream_id}) ->
  <<?STREAM_ID_ERROR:16>>;

to_conn_error({error, stream_state}) ->
  <<?STREAM_STATE_ERROR:16>>;

to_conn_error({error, final_offset}) ->
  <<?FINAL_OFFSET_ERROR:16>>;

to_conn_error({error, frame_format}) ->
  <<?FRAME_FORMAT_ERROR:16>>;

to_conn_error({error, transport_param}) ->
  <<?TRANSPORT_PARAMETER_ERROR:16>>;

to_conn_error({error, version_neg_error}) ->
  <<?VERSION_NEGOTIATION_ERROR:16>>;

to_conn_error({error, protocol_violation}) ->
  <<?PROTOCOL_VIOLATION:16>>;

to_conn_error({error, path_response}) ->
  <<?UNSOLICITED_PATH_RESPONSE:16>>;

to_conn_error(Other) ->
  ?DBG("Specific stream frame errors not supported yet: ~p~n", [Other]),
  <<100:16>>.




%% %% Base case for last Ack_Block when there are additional ack blocks.
%% %%parse_ack_blocks(Binary, Largest, 1, Acks) ->
%% %%  {Ack_Block, Rest} = parse_var_length(Binary),
%% %%  Ack = {Ack_Block, Largest},
%% %%  {[Ack | Acks], Rest};

%% parse_ack_blocks(Binary, Largest, Block_Count, Acks) ->
%%   {Ack_Block, Rest} = parse_var_length(Binary),
%%   {Gap_Block, Rest1} = parse_var_length(Rest),

%%   ?DBG("Gap_Block: ~p~n", [Gap_Block]),

%%   %% The Ack_Block is the range of packet numbers acknowledged in the 
%%   %% Ack_Block, so the Largest ack of the block needs to be kept with it.
%%   %% MAYBE: Change to a 3-tuple with Smallest ack as well.
%%   Ack = {Ack_Block, Largest},

%%   %% The next largest ack is the number of packets is given by:
%%   %% Next_Largest = Previous_Smallest - Gap - 2
%%   %% where, 
%%   %% Previous_Smallest = Largest - Ack_Block
%%   %% See Section 7.15.1
%%   Next_Largest = Largest - Ack_Block - Gap_Block,

%%   ?DBG("Ack_Block parsed: ~p~n", [Ack_Block]),

%%   parse_ack_blocks(Rest1, Next_Largest, Block_Count-1, [Ack | Acks]).

%% Build the Ack Block in the order given and returns the bitstring.

%% to_ack_block(Largest, [{Ack, _Largest} | Ack_Block]) ->
%%   Smallest = Largest - Ack,
%%   Ack_Bin = to_var_length(Ack),
%%   to_ack_blocks(Smallest, Ack_Block, [Ack_Bin]).

%% to_ack_blocks(Smallest, _Acks, _Ack_Block) when Smallest < 0 ->
%%   ?DBG("Error building ack block. Largest less than 0.~n", []),
%%   ?DBG("Acks left: ~p~n", [_Acks]),
%%   {error, badarg};

%% to_ack_blocks(_Smallest, [], Ack_Block) ->
%%   list_to_bitstring(lists:reverse(Ack_Block));

%% to_ack_blocks(Previous, [{Ack_Range, Next} | Rest], Ack_Block) ->
%%   Gap = Previous - Next,
%%   Gap_Bin = to_var_length(Gap),
%%   Smallest = Next - Ack_Range,
%%   Ack_Bin = to_var_length(Ack_Range),

%%   ?DBG("Gap: ~p, Smallest: ~p, Next: ~p~n", [Gap, Smallest, Next]),

%%   to_ack_blocks(Smallest, Rest, [Ack_Bin, Gap_Bin | Ack_Block]).
  


%% %% Stream frame parsing functions,
%% %% Returns:
%% %% {{stream_data, {Stream_ID, Offset, Message}}, Rest}
%% %% {{stream_close, {Stream_ID, Offset, Message}}, Rest}
%% %% 

%% %% TODO: Add potential type errors here. See Section 7.18
%% parse_stream(Binary, Type) ->
%%   {Stream_ID, Rest} = parse_var_length(Binary),
%%   parse_offset(Rest, Type, Stream_ID).


%% %% Offset of 0 means the offset is 0.
%% parse_offset(Binary, {0, _, _}=Type, Stream_ID) ->
%%   parse_length(Binary, Type, {Stream_ID, 0});

%% %% Offset of 1 means the frame has a variable length offset given.
%% parse_offset(Binary, {1, _, _}=Type, Stream_ID) ->
%%   {Offset, Rest} = parse_var_length(Binary),
%%   parse_length(Rest, Type, {Stream_ID, Offset});

%% parse_offset(_, Type, _) ->
%%   ?DBG("Invalid Offset Stream Type: ~p~n", [Type]),
%%   {error, stream}.

%% %% Len of 0 means the message is the remainder of the packet.
%% parse_length(Binary, {_, 0, _}=Type, {Stream_ID, Offset}) ->
%%   parse_fin(<<>>, Type, {Stream_ID, Offset, Binary});

%% %% Len of 1 means the stream has a message of variable length.
%% parse_length(Binary, {_, 1, _}=Type, {Stream_ID, Offset}) ->
%%   {Length, Rest} = parse_var_length(Binary),
%%   {Message, Rest1} = parse_message(Rest, Length),
%%   parse_fin(Rest1, Type, {Stream_ID, Offset, Message});

%% parse_length(_, Type, _) ->
%%   ?DBG("Invalid Length Stream Type: ~p~n", [Type]),
%%   {error, stream}.


%% %% Fin of 0 means the stream is still open.
%% parse_fin(Binary, {_, _, 0}, Stream) ->
%%   {{stream_data, Stream}, Binary};

%% %% Fin of 1 means the stream is closed.
%% parse_fin(Binary, {_, _, 1}, Stream) ->
%%   {{stream_close, Stream}, Binary};

%% parse_fin(_, Type, _) ->
%%   ?DBG("Invalid Fin Stream Type: ~p~n", [Type]),
%%   {error, stream}.




