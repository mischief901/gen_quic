%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%%
%%% @end
%%% Created :  6 Jun 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_parser_vx_1).

%% API
-export([parse_packet/2]).

-compile(inline).

-include("quic_headers.hrl").
-include("quic_vx_1.hrl").


parse_packet(<<1:1, Type_Bin:7, _Vx:32, Packet/bits>>, Info) ->

  {ok, Type} = from_type(Type_Bin),  
  Packet_Info = Info#quic_packet{type=Type},

  parse_next(Packet, Packet_Info, [long_header], long_header());

parse_packet(<<0:1, Key:1, 1:1, 1:1, 0:1, Reserved:3, Packet/bits>>, Info) ->

  Packet_Info = Info#quic_packet{key_phase=Key, reserve=Reserved},
  parse_next(Packet, Packet_Info, [short_header], short_header());

parse_packet(Other, Packet_Info) ->
  ?DBG("Error parsing packet: ~p~n", [Other]),
  ?DBG("Packet: ~p~n", [Packet_Info]),
  {error, badarg}.


%% These functions are the list of functions to call when a specific type is 
%% parsed. This enables the entire packet to be parsed with optimized 
%% sub-binary creation and allows for easy changes to the frame headers.
%% The list must be of valid function names. The dispatch function is 
%% parse_next.
%% Custom function entries must be added to the parse_next case statement.
%% The last function call should always be parse_frame unless the entire 
%% packet is parsed.
%% Potentially move all of these into a different module.

%% Long headers
long_header() -> 
  [parse_conn_ids, 
   parse_var_length,
   parse_pkt_num,
   validate_header,
   parse_frame].

%% Short header
short_header() -> 
  [parse_short_id, 
   parse_pkt_num, 
   validate_header, 
   parse_frame].

%% Padding and Ping just loop back to parse_frame.
padding() -> [parse_frame].

ping() -> [parse_frame].

%% Conn_Close and App_Close read an error, message length, and message.
conn_close() -> 
  [parse_conn_error, 
   parse_message, 
   parse_frame].

app_close() -> 
  [parse_app_error, 
   parse_message, 
   parse_frame].

%% Reset Stream reads a stream_id, app_error, and last stream offset.
rst_stream() -> 
  [parse_var_length, 
   parse_app_error, 
   parse_var_length, 
   parse_frame].

%% Max_Data and Max_Stream_ID read a variable integer, respectively.
max_data() -> 
  [parse_var_length, 
   parse_frame].

max_stream_id() -> 
  [parse_var_length, 
   parse_frame].

%% Max_Stream_Data parses the stream ID and data limit.
max_stream_data() -> 
  [parse_var_length, 
   parse_var_length, 
   parse_frame].

%% Blocked and Stream_ID_Blocked reads the wanted value above limit.
data_blocked() -> 
  [parse_var_length, 
   parse_frame].

stream_id_blocked() -> 
  [parse_var_length, 
   parse_frame].

%% Stream_Data_Blocked reads the stream ID and the blocked value.
stream_data_blocked() -> 
  [parse_var_length,
   parse_var_length,
   parse_frame].

%% New_Conn_ID reads a sequence number and a new connection ID with the
%% 128 bit stateless retry token.
new_conn_id() -> 
  [parse_var_length, 
   parse_conn_id, 
   parse_token, 
   parse_frame].

%% Stop_Sending reads a stream id and app error code
stop_sending() -> 
  [parse_var_length, 
   parse_app_error,
   parse_frame].

%% ack_frame reads the largest ack in the ack block, the ack_delay, and the
%% number of blocks/gaps in the ack_block then parses the ack_block.
ack_frame() -> 
  [parse_var_length, 
   parse_var_length,
   parse_var_length,
   parse_ack_blocks,
   add_end_ack,
   parse_frame].

%% Path_Challenge and Path_Response read the 64 bit random Nonce for
%% the path challenge and response protocol.
path_challenge() -> 
  [parse_challenge, 
   parse_frame].

path_response() -> 
  [parse_challenge, 
   parse_frame].

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
stream_length(0) -> [validate_packet];
stream_length(1) -> [parse_var_length, parse_message, parse_frame].

%% The parse_next function is a dispatch function that calls the next item to
%% parse in the frame header. This is necessary so that the sub-binary
%% optimizations can be utilized. Calling Fun(Packet, ...) is too dynamic for the
%% compiler to allow the optimizations.

parse_next(<<Packet/bits>>, Packet_Info, Acc, [Next_Fun | Funs]) ->
  case Next_Fun of
    add_end_ack ->
      %% This adds an atom to the stack to indicate the end of an ack block.
      parse_next(Packet, Packet_Info, [end_ack_block | Acc], Funs);

    parse_short_id ->
      parse_short_id(Packet, Packet_Info, Acc, Funs, 
                     Packet_Info#quic_packet.src_conn_ID_len);

    parse_pkt_num ->
      parse_pkt_num(Packet, Packet_Info, Acc, Funs);

    parse_conn_ids ->
      parse_conn_ids(Packet, Packet_Info, Acc, Funs);

    validate_header ->
      validate_header(Packet, Packet_Info, Acc, Funs);

    validate_packet ->
      validate_packet(Packet, Packet_Info, Acc, Funs);

    parse_frame ->
      parse_frame(Packet, Packet_Info, Acc);

    parse_var_length ->
      parse_var_length(Packet, Packet_Info, Acc, Funs);

    parse_conn_error ->
      parse_conn_error(Packet, Packet_Info, Acc, Funs);

    parse_app_error ->
      parse_app_error(Packet, Packet_Info, Acc, Funs);

    parse_message ->
      parse_message(Packet, Packet_Info, Acc, Funs);

    parse_ack_blocks ->
      parse_ack_blocks(Packet, Packet_Info, Acc, Funs);

    parse_token ->
      parse_token(Packet, Packet_Info, Acc, Funs);

    parse_conn_id ->
      parse_conn_id(Packet, Packet_Info, Acc, Funs)
  end;

parse_next(<<>>, Packet_Info, Acc, []) ->
  validate_packet(Packet_Info, Acc);

parse_next(<<>>, _Packet_Info, _Acc, Funs) ->
  ?DBG("Error with parsing dispatch functions: ~p~n", [Funs]),
  {error, badarg}.


validate_header(<<Packet/bits>>, Info, [short_header], Funs) ->
  parse_next(Packet, Info, [], Funs);

validate_header(<<Packet/bits>>, Info, [Payload_Len, long_header], Funs) ->
  parse_next(Packet, Info#quic_packet{payload_len=Payload_Len}, [], Funs);

validate_header(_Other, Info, Acc, Funs) ->
  ?DBG("Header not correctly validated: ~p~n", [Acc]),
  ?DBG("Funs: ~p~n", [Funs]),
  ?DBG("Packet_Info: ~p~n", [Info]),
  {error, protocol_violation}.

%% Not optimizable. Called when the stream uses the remainder of the packet
%% If any funs are remaining, an internal error is thrown.
validate_packet(<<Message/binary>>, Pkt_Info, Stack, []) ->
  ?DBG("Adding remainder of Message to Stack: ~p~n", [byte_size(Message)]),
  validate_packet(Pkt_Info, [<<Message/binary>> | Stack]);

validate_packet(Other, Pkt_Info, Stack, Funs) ->
  ?DBG("Packet not correctly validated: ~p~n", [Stack]),
  ?DBG("Funs remaining: ~p~n", [Funs]),
  ?DBG("Pkt_Info: ~p~n", [Pkt_Info]),
  ?DBG("Binary: ~p~n", [Other]),
  {error, internal}.

%% Crawls through the Stack and places items into the correct records.
%% Pushes onto Acc (putting the payload back in order)
%% Returns when stack is empty.
validate_packet(Pkt_Info, Stack) ->
  validate_packet(Pkt_Info, Stack, []).

validate_packet(Pkt_Info, [], Acc) ->
  {ok, Pkt_Info#quic_packet{payload = Acc}};

%% 0 - item frames
validate_packet(Pkt_Info, [ping | Rest], Acc) ->
  validate_packet(Pkt_Info, Rest, [#quic_frame{type=ping} | Acc]);


%% 1 - item frames
validate_packet(Pkt_Info, [Max_Data, max_data | Rest], Acc) ->
  Frame = #quic_frame{
             type=max_data, 
             data=Max_Data
            },
  validate_packet(Pkt_Info, Rest, [Frame | Acc]);

validate_packet(Pkt_Info, [Max_ID, max_stream_id | Rest], Acc) ->
  Frame = #quic_frame{
             type=max_stream_id, 
             data=Max_ID
            },
  validate_packet(Pkt_Info, Rest, [Frame | Acc]);

validate_packet(Pkt_Info, [Offset, data_blocked | Rest], Acc) ->
  Frame = #quic_frame{
             type=data_blocked, 
             data=Offset
            },
  validate_packet(Pkt_Info, Rest, [Frame | Acc]);

validate_packet(Pkt_Info, [Stream_ID, stream_id_blocked | Rest], Acc) ->
  Frame = #quic_frame{
             type=stream_id_blocked, 
             data=Stream_ID
            },
  validate_packet(Pkt_Info, Rest, [Frame | Acc]);

validate_packet(Pkt_Info, [Challenge, path_challenge | Rest], Acc) ->
  Frame = #quic_frame{
             type=path_challenge, 
             data=Challenge
            },
  validate_packet(Pkt_Info, Rest, [Frame | Acc]);

validate_packet(Pkt_Info, [Challenge, path_response | Rest], Acc) ->
  Frame = #quic_frame{
             type=path_response, 
             data=Challenge
            },
  validate_packet(Pkt_Info, Rest, [Frame | Acc]);

%% 2 - item frames
validate_packet(Pkt_Info, 
                [App_Error, Stream_ID, stop_sending | Rest], 
                Acc) ->

  Frame = #quic_frame{type=stop_sending, data={Stream_ID, App_Error}},
  validate_packet(Pkt_Info, Rest, [Frame | Acc]);

validate_packet(Pkt_Info, 
                [Offset, Stream_ID, stream_data_blocked | Rest], 
                Acc) ->

  <<_:60, Type:1, Owner:1>> = <<Stream_ID:62>>,

  Frame = #quic_stream{
             stream_id = Stream_ID,
             offset = Offset,
             owner = Owner,
             type = Type,
             data = stream_data_blocked
            },

  validate_packet(Pkt_Info, Rest, [Frame | Acc]);

validate_packet(Pkt_Info, 
                [Max_Stream_Data, Stream_ID, max_stream_data | Rest], 
                Acc) ->

  <<_:60, Type:1, Owner:1>> = <<Stream_ID:62>>,

  Frame = #quic_stream{
             stream_id = Stream_ID,
             max_data = Max_Stream_Data,
             owner = Owner,
             type = Type,
             data = max_stream_data
            },

  validate_packet(Pkt_Info, Rest, [Frame | Acc]);

validate_packet(Pkt_Info, 
                [Message, App_Error, app_close | Rest], 
                Acc) ->

  Frame = #quic_frame{
             type=app_close, 
             data={App_Error, Message}
            },

  validate_packet(Pkt_Info, Rest, [Frame | Acc]);

validate_packet(Pkt_Info, 
                [Message, Conn_Error, conn_close | Rest], 
                Acc) ->

  Frame = #quic_frame{
             type=conn_close, 
             data={Conn_Error, Message}
            },

  validate_packet(Pkt_Info, Rest, [Frame | Acc]);

%% 3 - item frames
validate_packet(Pkt_Info, 
                [Offset, App_Error, Stream_ID, rst_stream | Rest], 
                Acc) ->

  Frame = #quic_frame{
             type = rst_stream,
             data = {Stream_ID, App_Error, Offset}
            },

  validate_packet(Pkt_Info, Rest, [Frame | Acc]);

validate_packet(Pkt_Info, 
                [Token, Conn_ID, Seq_Num, new_conn_id | Rest], 
                Acc) ->

  Frame = #quic_frame{
             type = new_conn_id,
             data = {Seq_Num, Conn_ID, Token}
            },

  validate_packet(Pkt_Info, Rest, [Frame | Acc]);

%% Stream items either 1 item, 2 items, 3 items, or 4 items.
%% Either stream_data or stream_close type.
validate_packet(Pkt_Info, 
                [Message, Stream_ID, {stream_data, 0, _} | Rest], 
                Acc) ->

  <<_:60, Type:1, Owner:1>> = <<Stream_ID:62>>,

  Frame = #quic_stream{
             stream_id = Stream_ID,
             offset = 0,
             open = 1,
             current_data = 0,
             owner = Owner,
             type = Type,
             data = Message
            },
  validate_packet(Pkt_Info, Rest, [Frame | Acc]);

validate_packet(Pkt_Info, 
                [Message, Stream_ID, {stream_close, 0, _} | Rest], 
                Acc) ->

  <<_:60, Type:1, Owner:1>> = <<Stream_ID:62>>,

  Frame = #quic_stream{
             stream_id = Stream_ID,
             offset = 0,
             current_data = 0,
             open = 0,
             owner = Owner,
             type = Type,
             data = Message
            },
  validate_packet(Pkt_Info, Rest, [Frame | Acc]);  

%% Offset set
validate_packet(Pkt_Info, 
                [Message, Offset, Stream_ID, {stream_data, 1, _} | Rest], 
                Acc) ->

  <<_:60, Type:1, Owner:1>> = <<Stream_ID:62>>,

  Frame = #quic_stream{
             stream_id = Stream_ID,
             offset = Offset,
             open = 1,
             owner = Owner,
             type = Type,
             data = Message
            },
  validate_packet(Pkt_Info, Rest, [Frame | Acc]);

validate_packet(Pkt_Info, 
                [Message, Offset, Stream_ID, {stream_close, 1, _} | Rest], 
                Acc) ->

  <<_:60, Type:1, Owner:1>> = <<Stream_ID:62>>,

  Frame = #quic_stream{
             stream_id = Stream_ID,
             offset = Offset,
             open = 0,
             owner = Owner,
             type = Type,
             data = Message
            },
  validate_packet(Pkt_Info, Rest, [Frame | Acc]);

%% Ack block. This is the only one that keeps the reversed ordered.
%% Smallest to Largest makes more sense to process on the connection side.
%% Begins with end_ack_block atom and ends with ack_frame atom.
validate_packet(Pkt_Info, [end_ack_block | Rest], Acc) ->
  construct_ack_frame(Pkt_Info, Rest, Acc, [], 0).

%% 
construct_ack_frame(#quic_packet{ack_frame = Ack} = Pkt_Info, 
                    [Current_Count, Delay, Largest, ack_frame], 
                    Frame_Acc, Acks, Current_Count) ->
  
  validate_packet(Pkt_Info#quic_packet{ack_frame=




parse_conn_ids(<<DCIL:4, SCIL:4,
                 Dest_Conn:DCIL/unit:8,
                 Src_Conn:SCIL/unit:8,
                 Rest/bits>>,
               #quic_packet{
                  dest_conn_ID = Dest,
                  src_conn_ID = Src
                 } = Info,
               Acc, Funs) ->

  case validate_conn(Dest, <<Dest_Conn>>) of
    true ->
      case validate_conn(Src, <<Src_Conn>>) of
        true ->
          %% Dest and Src have not been set yet.
          Packet_Info = Info#quic_packet{
                          dest_conn_ID = <<Src_Conn>>,
                          src_conn_ID = <<Dest_Conn>>,
                          dest_conn_ID_len = SCIL,
                          src_conn_ID_len = DCIL
                         },
          parse_next(Rest, Packet_Info, Acc, Funs);

        false ->
          ?DBG("Connection IDs do not match.~n", []),
          ?DBG("Dest: ~p~n~p~n", [Dest, <<Dest_Conn>>]),
          ?DBG("Src: ~p~n~p~n", [Src, <<Src_Conn>>]),
          {error, protocol_violation}
      end;

    _Other ->
      ?DBG("Connection IDs do not match.~n", []),
      ?DBG("Dest: ~p~n~p~n", [Dest, <<Dest_Conn>>]),
      ?DBG("Src: ~p~n~p~n", [Src, <<Src_Conn>>]),
      {error, protocol_violation}
  end.

validate_conn(Conn, Conn) -> true;
validate_conn(_, _) -> false.

parse_pkt_num(<<0:1, Pkt_Num:7, Rest/bits>>, Packet_Info, Acc, Funs) ->
  parse_next(Rest, Packet_Info#quic_packet{pkt_num = Pkt_Num}, Acc, Funs);

parse_pkt_num(<<2:2, Pkt_Num:14, Rest/bits>>, Packet_Info, Acc, Funs) ->
  parse_next(Rest, Packet_Info#quic_packet{pkt_num = Pkt_Num}, Acc, Funs);

parse_pkt_num(<<3:2, Pkt_Num:30, Rest/bits>>, Packet_Info, Acc, Funs) ->
  parse_next(Rest, Packet_Info#quic_packet{pkt_num = Pkt_Num}, Acc, Funs).


parse_short_id(<<Packet/bits>>, Packet_Info, Acc, Funs, Length) ->
  <<Dest_Conn:Length/unit:8, Rest/bits>> = Packet,

  case Packet_Info#quic_packet.src_conn_ID of
    <<Dest_Conn>> ->
      %% Success
      parse_next(Rest, Packet_Info, Acc, Funs);

    Other ->
      %% Failure. These should be equal.
      ?DBG("Destination connection ID does not match:~n~p~n~p~n", 
           [Other, <<Dest_Conn>>]),
      {error, protocol_violation}
  end.

%% Not called anymore. Leaving for debug purposes.
%% parse_frames(<<Binary/bits>>, Packet_Info) ->
%%   parse_next(Binary, Packet_Info, [], [parse_frame]).

parse_frame(<<0:1, 0:1, 0:1, 0:1, Type:4, Rest/bits>>, Pkt_Info, Stack) ->
  case Type of
    ?PADDING ->
      ?DBG("Padding.~n", []),
      parse_next(Rest, Pkt_Info, Stack, padding());

    ?RST_STREAM ->
      ?DBG("Reset Stream.~n", []),
      parse_next(Rest, Pkt_Info, [rst_stream | Stack], rst_stream());

    ?CONN_CLOSE ->
      ?DBG("Connection Close.~n", []),
      parse_next(Rest, Pkt_Info, [conn_close | Stack], conn_close());

    ?APP_CLOSE ->
      ?DBG("Application Close.~n", []),
      parse_next(Rest, Pkt_Info, [app_close | Stack], app_close());

    ?MAX_DATA ->
      ?DBG("Max Data.~n", []),
      parse_next(Rest, Pkt_Info, [max_data | Stack], max_data());

    ?MAX_STREAM_DATA ->
      ?DBG("Max Stream Data.~n", []),
      parse_next(Rest, Pkt_Info, [max_stream_data | Stack], max_stream_data());

    ?MAX_STREAM_ID ->
      ?DBG("Max Stream ID.~n", []),
      parse_next(Rest, Pkt_Info, [max_stream_id | Stack], max_stream_id());

    ?PING ->
      ?DBG("Ping.~n", []),
      parse_next(Rest, Pkt_Info, [ping | Stack], ping());

    ?BLOCKED ->
      ?DBG("Blocked.~n", []),
      parse_next(Rest, Pkt_Info, [data_blocked | Stack], data_blocked());

    ?STREAM_BLOCKED ->
      ?DBG("Stream Blocked.~n", []),
      parse_next(Rest, Pkt_Info, [stream_data_blocked | Stack], stream_data_blocked());

    ?STREAM_ID_BLOCKED ->
      ?DBG("Stream ID Blocked.~n", []),
      parse_next(Rest, Pkt_Info, [stream_id_blocked | Stack], stream_id_blocked());

    ?NEW_CONN_ID ->
      ?DBG("New Connection ID.~n", []),
      parse_next(Rest, Pkt_Info, [new_conn_id | Stack], new_conn_id());

    ?STOP_SENDING ->
      ?DBG("Stop Sending.~n", []),
      parse_next(Rest, Pkt_Info, [stop_sending | Stack], stop_sending());

    ?ACK_FRAME ->
      ?DBG("Ack Frame.~n", []),
      parse_next(Rest, Pkt_Info, [ack_frame | Stack], ack_frame());

    ?PATH_CHALLENGE ->
      ?DBG("Path Challenge.~n", []),
      parse_next(Rest, Pkt_Info, [path_challenge | Stack], path_challenge());

    ?PATH_RESPONSE ->
      ?DBG("Path Response.~n", []),
      parse_next(Rest, Pkt_Info, [path_response | Stack], path_response())
  end;

parse_frame(<<1:4, 0:1, Off:1, Len:1, 0:1 , Rest/bits>>, Pkt_Info, Stack) ->
  parse_next(Rest, Pkt_Info, 
             [{stream_data, Off, Len} | Stack], 
             stream({Off, Len}));

parse_frame(<<1:4, 0:1, Off:1, Len:1, 1:1 , Rest/bits>>, Pkt_Info, Stack) ->
  parse_next(Rest, Pkt_Info, 
             [{stream_close, Off, Len} | Stack], 
             stream({Off, Len}));

parse_frame(Other, Pkt_Info, Stack) ->
  ?DBG("Not a proper frame type: ~p.~n", [Other]),
  ?DBG("Packet_Info: ~p~n", [Pkt_Info]),
  ?DBG("Frames: ~p~n", [Stack]),
  {error, badarg}.


parse_app_error(<<?STOPPING:16, Rest/binary>>, Pkt_Info, Stack, Funs) ->
  parse_next(Rest, Pkt_Info, [stopping | Stack], Funs);

parse_app_error(<<_App_Error:16, Rest/binary>>, Pkt_Info, Stack, Funs) ->
  parse_next(Rest, Pkt_Info, [app_error | Stack], Funs);

parse_app_error(Other, Pkt_Info, Stack, Funs) ->
  ?DBG("Error parsing application error: ~p~n", [Other]),
  ?DBG("Packet_Info: ~p~n", [Pkt_Info]),
  ?DBG("Frames: ~p~n", [Stack]),
  ?DBG("Funs: ~p~n", [Funs]),
  {error, badarg}.


parse_conn_error(<<Type:16, Rest/bits>>, Pkt_Info, Stack, Funs) ->
  parse_next(Rest, Pkt_Info, [conn_error(Type) | Stack], Funs).


conn_error(?NO_ERROR) ->
  ok;
conn_error(?INTERNAL_ERROR) ->
  {error, internal};
conn_error(?SERVER_BUSY) ->
  {error, server_busy};
conn_error(?FLOW_CONTROL_ERROR) ->
  {error, flow_control};
conn_error(?STREAM_ID_ERROR) ->
  {error, stream_id};
conn_error(?STREAM_STATE_ERROR) ->
  {error, stream_state};
conn_error(?FINAL_OFFSET_ERROR) ->
  {error, final_offset};
conn_error(?FRAME_FORMAT_ERROR) ->
  {error, frame_format};
conn_error(?TRANSPORT_PARAMETER_ERROR) ->
  {error, transport_param};
conn_error(?VERSION_NEGOTIATION_ERROR) ->
  {error, version_neg_error};
conn_error(?PROTOCOL_VIOLATION) ->
  {error, protocol_violation};
conn_error(?UNSOLICITED_PATH_RESPONSE) ->
  {error, path_response};
conn_error(Frame_Error) when 
    Frame_Error >= 100, Frame_Error =< 123 ->
  {error, frame_error};
%% TODO: frame_error(Frame_Error)
conn_error(Other) ->
  ?DBG("Unsupported error: ~p~n", [Other]),
  {error, badarg}.



parse_conn_id(<<ID_Len:4, Conn_ID:ID_Len, Rest/bits>>, Pkt_Info, Stack, Funs) ->
  ?DBG("Connection ID parsed: ~p~n", [Conn_ID]),
  ?DBG("Length: ~p~n", [ID_Len]),
  parse_next(Rest, Pkt_Info, [Conn_ID, ID_Len | Stack], Funs).

parse_token(<<Token:128, Rest/bits>>, Pkt_Info, Stack, Funs) ->
  ?DBG("Parsing 128 bit token: ~p~n", [Token]),
  parse_next(Rest, Pkt_Info, [Token | Stack], Funs).


parse_ack_blocks(<<Binary/bits>>, Pkt_Info, [Count | _]=Stack, Funs) ->
  ?DBG("Parsing ack block of size: ~p~n", [Count]),
  parse_ack_blocks(Binary, Pkt_Info, Stack, Funs, Count).


%% Parse one value for the final ack range.
parse_ack_blocks(<<Binary/bits>>, Pkt_Info, Stack, Funs, 0) ->
  parse_next(Binary, Pkt_Info, Stack, [parse_var_length, parse_var_length | Funs]);

%% Parse two values, one ack range and one gap range.
parse_ack_blocks(<<Binary/bits>>, Pkt_Info, Stack, Funs, Count) ->
  parse_ack_blocks(Binary, Pkt_Info, Stack, [parse_var_length, parse_var_length | Funs], Count-1).


parse_var_length(<<Offset:2, Rest/bits>>, Pkt_Info, Stack, Funs) ->
  parse_offset(Rest, Pkt_Info, Stack, Funs, Offset).

parse_offset(<<Integer:6, Rest/bits>>, Pkt_Info, Stack, Funs, 0) ->
  parse_next(Rest, Pkt_Info, [Integer | Stack], Funs);

parse_offset(<<Integer:14, Rest/bits>>,Pkt_Info, Stack, Funs, 1) ->
  parse_next(Rest, Pkt_Info, [Integer | Stack], Funs);

parse_offset(<<Integer:30, Rest/bits>>, Pkt_Info, Stack, Funs, 2) ->
  parse_next(Rest, Pkt_Info, [Integer | Stack], Funs);

parse_offset(<<Integer:62, Rest/bits>>, Pkt_Info, Stack, Funs, 3) ->
  parse_next(Rest, Pkt_Info, [Integer | Stack], Funs);

parse_offset(<<_Error/bits>>, Pkt_Info, Stack, _Funs, Offset) ->
  ?DBG("Invalid Offset: ~p~n", [Offset]),
  ?DBG("Packet_Info: ~p~nFrame: ~p~n", [Pkt_Info, Stack]),
  {error, badarg}.


%% This is to allow for the sub-binary creation to be delayed.
parse_message(<<Offset:2, Rest/bits>>, Pkt_Info, Stack, Funs) ->  
  parse_offset_message(Rest, Pkt_Info, Stack, Funs, Offset).

parse_message(<<Binary/bits>>, Pkt_Info, Stack, Funs, Length) ->
  <<Message:Length, Rest/bits>> = Binary,
  parse_next(Rest, Pkt_Info, [<<Message:Length>> | Stack], Funs).

parse_offset_message(<<Integer:6, Rest/bits>>, Pkt_Info, Stack, Funs, 0) ->
  parse_message(Rest, Pkt_Info, Stack, Funs, Integer);

parse_offset_message(<<Integer:14, Rest/bits>>,Pkt_Info, Stack, Funs, 1) ->
  parse_message(Rest, Pkt_Info, Stack, Funs, Integer);

parse_offset_message(<<Integer:30, Rest/bits>>, Pkt_Info, Stack, Funs, 2) ->
  parse_message(Rest, Pkt_Info, Stack, Funs, Integer);

parse_offset_message(<<Integer:62, Rest/bits>>, Pkt_Info, Stack, Funs, 3) ->
  parse_message(Rest, Pkt_Info, Stack, Funs, Integer);

parse_offset_message(<<_Error/bits>>, Pkt_Info, Stack, _Funs, Offset) ->
  ?DBG("Invalid Offset: ~p~n", [Offset]),
  ?DBG("Packet_Info: ~p~nFrame: ~p~n", [Pkt_Info, Stack]),
  {error, badarg}.


%% Parses Long header type
from_type(<<1:1, Type:7>>) ->
  case Type of
    ?INITIAL ->
      {ok, initial};
    ?RETRY ->
      {ok, retry};
    ?HANDSHAKE ->
      {ok, handshake};
    ?PROTECTED ->
      {ok, protected};
    Other ->
      ?DBG("Unsupported long header type received: ~p~n", [Other]),
      ?DBG("Type: ~p~n", [Type]),
      {error, badarg}
  end;

from_type(Other) ->
  ?DBG("Incorrect header format received: ~p~n", [Other]),
  {error, badarg}.

