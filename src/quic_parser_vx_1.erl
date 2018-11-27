%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%%  The ack parsing and ack_frame creation are wrong. Needs changing.
%%% @end
%%% Created :  6 Jun 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_parser_vx_1).

%% API
-export([parse_frames/2]).

-compile(inline).

-include("quic_headers.hrl").
-include("quic_vx_1.hrl").


-spec parse_frames(Payload, Data) -> Result when
    Payload :: binary(),
    Data :: #quic_data{},
    Result :: {Data, Frames, Acks, TLS_Info} |
              {error, Reason},
    Frames :: quic_frame(),
    Acks :: quic_frame(),
    TLS_Info :: #tls_record{},
    Reason :: gen_quic:error().

parse_frames(<<Frames/binary>>, Data) ->
  parse_frame(Frames, Data, []).

%% These functions are the list of functions to call when a specific type is 
%% parsed. This enables the entire packet to be parsed with optimized 
%% sub-binary creation and allows for easy changes to the frame headers.
%% The list must be of valid function names. The dispatch function is 
%% parse_next.
%% Custom function entries must be added to the parse_next case statement.
%% The last function call should always be parse_frame unless the entire 
%% packet is parsed.
%% Potentially move all of these into a different module.

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
      parse_token(Packet, Packet_Info, Acc, Funs)
  end;

parse_next(<<>>, Packet_Info, Acc, []) ->
  validate_packet(Packet_Info, Acc);

parse_next(<<>>, _Packet_Info, _Acc, Funs) ->
  {error, protocol_violation}.


%% Called when the stream uses the remainder of the packet
%% If any funs are remaining, a protocol violation error is thrown.
%% TODO: Needs different name.
validate_packet(<<Message/binary>>, Pkt_Info, Stack, []) ->
  validate_packet(Pkt_Info, [Message | Stack]);

validate_packet(Other, Pkt_Info, Stack, Funs) ->
  {error, protocol_violation}.

%% Crawls through the Stack and places items into the correct records.
%% Pushes onto Acc (putting the payload back in order)
%% Returns when stack is empty.
%% TODO: Add Crypto frame and crypto acc.
validate_packet(Pkt_Info, Stack) ->
  validate_packet(Pkt_Info, Stack, [], [], none).

validate_packet(Pkt_Info, [], Acc, Ack_Frames, TLS_Info) ->
  {ok, Pkt_Info, Acc, Ack_Frames, TLS_Info};

%% 0 - item frames
validate_packet(Pkt_Info, [ping | Rest], Acc, Ack_Frames, TLS_Info) ->
  validate_packet(Pkt_Info, Rest, [#{type => ping} | Acc], Ack_Frames, TLS_Info);


%% 1 - item frames
validate_packet(Pkt_Info, [Max_Data, max_data | Rest], Acc, Ack_Frames, TLS_Info) ->
  Frame = #{
            type => max_data, 
            max_data => Max_Data
           },
  validate_packet(Pkt_Info, Rest, [Frame | Acc], Ack_Frames, TLS_Info);

validate_packet(Pkt_Info, [Max_ID, max_stream_id | Rest], Acc, Ack_Frames, TLS_Info) ->
  Frame = #{
            type => max_stream_id, 
            max_stream_id => Max_ID
           },
  validate_packet(Pkt_Info, Rest, [Frame | Acc], Ack_Frames, TLS_Info);

validate_packet(Pkt_Info, [Offset, data_blocked | Rest], Acc, Ack_Frames, TLS_Info) ->
  Frame = #{
            type => data_blocked, 
            offset => Offset
           },
  validate_packet(Pkt_Info, Rest, [Frame | Acc], Ack_Frames, TLS_Info);

validate_packet(Pkt_Info, [Stream_ID, stream_id_blocked | Rest], Acc, Ack_Frames, TLS_Info) ->
  Frame = #{
            type => stream_id_blocked, 
            stream_id => Stream_ID
            },
  validate_packet(Pkt_Info, Rest, [Frame | Acc], Ack_Frames, TLS_Info);

validate_packet(Pkt_Info, [Challenge, path_challenge | Rest], Acc, Ack_Frames, TLS_Info) ->
  Frame = #{
            type => path_challenge, 
            challenge => Challenge
           },
  validate_packet(Pkt_Info, Rest, [Frame | Acc], Ack_Frames, TLS_Info);

validate_packet(Pkt_Info, [Challenge, path_response | Rest], Acc, Ack_Frames, TLS_Info) ->
  Frame = #{
            type => path_response, 
            challenge => Challenge
           },
  validate_packet(Pkt_Info, Rest, [Frame | Acc], Ack_Frames, TLS_Info);

%% 2 - item frames
validate_packet(Pkt_Info, 
                [App_Error, Stream_ID, stop_sending | Rest], 
                Acc, Ack_Frames, TLS_Info) ->

  Frame = #{
            type => stop_sending, 
            stream_id => Stream_ID, 
            error_code => App_Error
           },

  validate_packet(Pkt_Info, Rest, [Frame | Acc], Ack_Frames, TLS_Info);

validate_packet(Pkt_Info, 
                [Offset, Stream_ID, stream_data_blocked | Rest], 
                Acc, Ack_Frames, TLS_Info) ->

  <<_:60, Type:1, Owner:1>> = <<Stream_ID:62>>,

  Frame = #{
            type => stream_data_blocked,
            stream_id => Stream_ID,
            offset => Offset,
            stream_owner => Owner,
            stream_type => Type
           },

  validate_packet(Pkt_Info, Rest, [Frame | Acc], Ack_Frames, TLS_Info);

validate_packet(Pkt_Info, 
                [Max_Stream_Data, Stream_ID, max_stream_data | Rest], 
                Acc, Ack_Frames, TLS_Info) ->

  <<_:60, Type:1, Owner:1>> = <<Stream_ID:62>>,

  Frame = #{
            type => max_stream_data,
            stream_id => Stream_ID,
            max_stream_data => Max_Stream_Data,
            stream_owner => Owner,
            stream_type => Type
           },

  validate_packet(Pkt_Info, Rest, [Frame | Acc], Ack_Frames, TLS_Info);

validate_packet(Pkt_Info, 
                [Message, App_Error, app_close | Rest], 
                Acc, Ack_Frames, TLS_Info) ->

  Frame = #{
            type => app_close, 
            error_code => App_Error, 
            error_message => Message
           },

  validate_packet(Pkt_Info, Rest, [Frame | Acc], Ack_Frames, TLS_Info);

validate_packet(Pkt_Info, 
                [Message, Conn_Error, conn_close | Rest], 
                Acc, Ack_Frames, TLS_Info) ->

  Frame = #{
            type => conn_close, 
            error_code => Conn_Error, 
            error_message => Message
           },

  validate_packet(Pkt_Info, Rest, [Frame | Acc], Ack_Frames, TLS_Info);

%% 3 - item frames
validate_packet(Pkt_Info, 
                [Offset, App_Error, Stream_ID, rst_stream | Rest], 
                Acc, Ack_Frames, TLS_Info) ->

  Frame = #{
            type => rst_stream,
            stream_id => Stream_ID, 
            error_code => App_Error, 
            offset => Offset
           },

  validate_packet(Pkt_Info, Rest, [Frame | Acc], Ack_Frames, TLS_Info);

validate_packet(Pkt_Info, 
                [Token, Conn_ID, Seq_Num, new_conn_id | Rest], 
                Acc, Ack_Frames, TLS_Info) ->

  Frame = #{
            type => new_conn_id,
            conn_id => Conn_ID,
            token => Token,
            sequence => Seq_Num
           },

  validate_packet(Pkt_Info, Rest, [Frame | Acc], Ack_Frames, TLS_Info);

%% Stream items either 1 item, 2 items, 3 items, or 4 items.
%% Either stream_data or stream_close type.
validate_packet(Pkt_Info, 
                [Message, Stream_ID, {stream_data, 0, _} | Rest], 
                Acc, Ack_Frames, TLS_Info) ->

  <<_:60, Type:1, Owner:1>> = <<Stream_ID:62>>,

  Frame = #{
            type => stream_open,
            stream_id => Stream_ID,
            offset => 0,
            stream_owner => Owner,
            stream_type => Type,
            data => Message
           },
  validate_packet(Pkt_Info, Rest, [Frame | Acc], Ack_Frames, TLS_Info);

validate_packet(Pkt_Info,
                [Message, Stream_ID, {stream_close, 0, _} | Rest],
                Acc, Ack_Frames, TLS_Info) ->

  <<_:60, Type:1, Owner:1>> = <<Stream_ID:62>>,

  Frame = #{
            type => stream_close,
            stream_id => Stream_ID,
            offset => 0,
            stream_owner => Owner,
            stream_type => Type,
            data => Message
           },
  validate_packet(Pkt_Info, Rest, [Frame | Acc], Ack_Frames, TLS_Info);  

%% Offset set
validate_packet(Pkt_Info, 
                [Message, Offset, Stream_ID, {stream_data, 1, _} | Rest], 
                Acc, Ack_Frames, TLS_Info) ->

  <<_:60, Type:1, Owner:1>> = <<Stream_ID:62>>,

  Frame = #{
            type => stream_data,
            stream_id => Stream_ID,
            offset => Offset,
            stream_owner => Owner,
            stream_type => Type,
            data => Message
           },
  validate_packet(Pkt_Info, Rest, [Frame | Acc], Ack_Frames, TLS_Info);

validate_packet(Pkt_Info, 
                [Message, Offset, Stream_ID, {stream_close, 1, _} | Rest], 
                Acc, Ack_Frames, TLS_Info) ->

  <<_:60, Type:1, Owner:1>> = <<Stream_ID:62>>,

  Frame = #{
            type => stream_close,
            stream_id => Stream_ID,
            offset => Offset,
            stream_owner => Owner,
            stream_type => Type,
            data => Message
           },
  validate_packet(Pkt_Info, Rest, [Frame | Acc], Ack_Frames, TLS_Info);

%% Ack block. This is the only one that keeps the reversed ordered.
%% Smallest to Largest makes more sense to process on the connection side.
%% Begins with end_ack_block atom and ends with ack_frame atom.
%% This does traverse the entire ack block frame twice, so it is a potential
%% source of optimization.
%% TODO: Update this to something better.
validate_packet(Pkt_Info, [end_ack_block | Rest], Frames, Ack_Frames, TLS_Info) ->
  read_acks(Pkt_Info, Rest, Frames, Ack_Frames, TLS_Info, []).

%% Pops all ack ranges off the stack and into a new accumulator to allow
%% in order processessing of the ack ranges.
read_acks(Pkt_Info, [Ack_Block, Block_Count, Delay, Largest_Ack, ack_frame | Stack], 
          Frames, Ack_Frames, TLS_Info, Acc) ->

  Ack_Frame = #{
                type => ack_frame,
                largest_ack => Largest_Ack,
                smallest_ack => Largest_Ack,
                block_count => Block_Count,
                ack_delay => Delay
               },
  construct_ack_frame(Pkt_Info, Stack, Frames, Ack_Frames, 
                      TLS_Info, [Ack_Block | Acc], Ack_Frame);

read_acks(Pkt_Info, [Ack_Block, Gap_Block | Rest], Frames, Ack_Frames, TLS_Info, Acc) ->
  read_acks(Pkt_Info, Rest, Frames, Ack_Frames, TLS_Info, [Gap_Block, Ack_Block | Acc]).

%% Calculates the largest and smallest ack packet number in the frame
%% Pushes it onto the ack_frame list in #quic_data{}.

construct_ack_frame(Pkt_Info, Stack, Frames, Ack_Frames, 
                    TLS_Info, [Ack], 
                    #{
                      smallest_ack := Largest,
                      acks := Ack_List
                     } = Frame0) ->

  Smallest = Largest - Ack,
  
  New_Ack_Range = lists:seq(Smallest, Largest),
  
  Ack_Frame = Frame0#{
                      smallest_ack => Smallest,
                      acks => [New_Ack_Range | Ack_List]
                     },

  validate_packet(Pkt_Info, Stack, Frames, [Ack_Frame | Ack_Frames], TLS_Info);

%% The next largest ack is given by:
%% Next_Largest = Smallest - Gap - 2
%% where, 
%% Smallest = Largest - Ack
%% See Section 7.15.1
construct_ack_frame(Pkt_Info, Stack, Frames, Ack_Frames, 
                    TLS_Info, [Ack, Gap | Rest], 
                    #{
                      largest_ack := Largest,
                      smallest_ack := Smallest,
                      acks := Ack_List,
                      gaps := Gap_List
                     } = Frame0) ->

  Smallest_Ack = Smallest - Ack,

  New_Ack_Range = lists:seq(Smallest_Ack, Smallest),

  Next_Largest = Smallest_Ack - Gap - 2,

  New_Gap_Range = lists:seq(Next_Largest, Smallest_Ack),

  Ack_Frame = Frame0#{
                      smallest => Next_Largest,
                      acks => [New_Ack_Range | Ack_List],
                      gaps => [New_Gap_Range | Gap_List]
                     },

  construct_ack_frame(Pkt_Info, Stack, Frames, TLS_Info, Ack_Frames, Rest, Ack_Frame).


%% Not called anymore. Leaving for debug purposes.
%% parse_frames(<<Binary/bits>>, Packet_Info) ->
%%   parse_next(Binary, Packet_Info, [], [parse_frame]).

parse_frame(<<0:1, 0:1, 0:1, 0:1, Type:4, Rest/bits>>, Pkt_Info, Stack) ->
  case Type of
    ?PADDING ->
      parse_next(Rest, Pkt_Info, Stack, padding());

    ?RST_STREAM ->
      parse_next(Rest, Pkt_Info, [rst_stream | Stack], rst_stream());

    ?CONN_CLOSE ->
      parse_next(Rest, Pkt_Info, [conn_close | Stack], conn_close());

    ?APP_CLOSE ->
      parse_next(Rest, Pkt_Info, [app_close | Stack], app_close());

    ?MAX_DATA ->
      parse_next(Rest, Pkt_Info, [max_data | Stack], max_data());

    ?MAX_STREAM_DATA ->
      parse_next(Rest, Pkt_Info, [max_stream_data | Stack], max_stream_data());

    ?MAX_STREAM_ID ->
      parse_next(Rest, Pkt_Info, [max_stream_id | Stack], max_stream_id());

    ?PING ->
      parse_next(Rest, Pkt_Info, [ping | Stack], ping());

    ?BLOCKED ->
      parse_next(Rest, Pkt_Info, [data_blocked | Stack], data_blocked());

    ?STREAM_BLOCKED ->
      parse_next(Rest, Pkt_Info, [stream_data_blocked | Stack], stream_data_blocked());

    ?STREAM_ID_BLOCKED ->
      parse_next(Rest, Pkt_Info, [stream_id_blocked | Stack], stream_id_blocked());

    ?NEW_CONN_ID ->
      parse_next(Rest, Pkt_Info, [new_conn_id | Stack], new_conn_id());

    ?STOP_SENDING ->
      parse_next(Rest, Pkt_Info, [stop_sending | Stack], stop_sending());

    ?ACK_FRAME ->
      parse_next(Rest, Pkt_Info, [ack_frame | Stack], ack_frame());

    ?PATH_CHALLENGE ->
      parse_next(Rest, Pkt_Info, [path_challenge | Stack], path_challenge());

    ?PATH_RESPONSE ->
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

parse_frame(_Other, _Pkt_Info, _Stack) ->
  {error, badarg}.


parse_app_error(<<?STOPPING:16, Rest/binary>>, Pkt_Info, Stack, Funs) ->
  parse_next(Rest, Pkt_Info, [stopping | Stack], Funs);

parse_app_error(<<_App_Error:16, Rest/binary>>, Pkt_Info, Stack, Funs) ->
  parse_next(Rest, Pkt_Info, [app_error | Stack], Funs);

parse_app_error(Other, Pkt_Info, Stack, Funs) ->
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
  {error, badarg}.


parse_token(<<Token:128, Rest/bits>>, Pkt_Info, Stack, Funs) ->
  parse_next(Rest, Pkt_Info, [Token | Stack], Funs).


parse_ack_blocks(<<Binary/bits>>, Pkt_Info, [Count | _]=Stack, Funs) ->
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
  {error, badarg}.



