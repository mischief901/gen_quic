%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%%
%%% @end
%%% Created : 16 May 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_frame).

%% API

-compile(export_all).


-include("quic_headers.hrl").
-include("quic_vxx.hrl").

%%%===================================================================
%%% API
%%%===================================================================

%% TODO: Use records instead of tuples.

%% read_frame is built so that a packet (with frames in it) can be recursed
%% over once and parse a list of all the data in the packet.

%% MAYBE: A potential source of optimization is to switch the order on all
%% these tuples. It would keep the Binary info in the same register. Might be
%% caught and optimized by the compiler.
read_frame(<<0:1, 0:1, 0:1, 0:1, Type:4, Rest/binary>> = Binary) ->
  case Type of
    ?PADDING ->
      ?DBG("Padding.~n", []),
      {padding, Rest};

    ?RST_STREAM ->
      ?DBG("Reset Stream.~n", []),
      {Stream_ID, Rest1} = parse_var_length(Rest),
      {App_Error, Rest2} = parse_app_error(Rest1),
      {Offset, Rest3} = parse_var_length(Rest2),
      {{rst_stream, Stream_ID, App_Error, Offset}, Rest3};

    ?CONN_CLOSE ->
      ?DBG("Connection Close.~n", []),
      {Conn_Error, Rest1} = parse_conn_error(Rest),
      {Reason_Len, Rest2} = parse_var_length(Rest1),
      {Reason, Rest3} = parse_message(Rest2, Reason_Len),
      {{conn_close, Conn_Error, Reason}, Rest3};

    ?APP_CLOSE ->
      ?DBG("Application Close.~n", []),
      {App_Error, Rest1} = parse_app_error(Rest),
      {Reason_Len, Rest2} = parse_var_length(Rest1),
      {Reason, Rest3} = parse_message(Rest2, Reason_Len),
      {{app_close, App_Error, Reason}, Rest3};

    ?MAX_DATA ->
      ?DBG("Max Data.~n", []),
      {Max_Data, Rest1} = parse_var_length(Rest),
      {{max_data, Max_Data}, Rest1};

    ?MAX_STREAM_DATA ->
      ?DBG("Max Stream Data.~n", []),
      {Stream_ID, Rest1} = parse_var_length(Rest),
      {Max_Stream_Data, Rest2} = parse_var_length(Rest1),
      {{max_stream_data, Stream_ID, Max_Stream_Data}, Rest2};

    ?MAX_STREAM_ID ->
      ?DBG("Max Stream ID.~n", []),
      {Max_Stream_ID, Rest1} = parse_var_length(Rest),
      {{max_stream_id, Max_Stream_ID}, Rest1};

    ?PING ->
      ?DBG("Ping.~n", []),
      {ping, Rest};

    ?BLOCKED ->
      ?DBG("Blocked.~n", []),
      {Offset, Rest1} = parse_var_length(Rest),
      {{blocked, Offset}, Rest1};

    ?STREAM_BLOCKED ->
      ?DBG("Stream Blocked.~n", []),
      {Stream_ID, Rest1} = parse_var_length(Rest),
      {Offset, Rest2} = parse_var_length(Rest1),
      {{stream_blocked, Stream_ID, Offset}, Rest2};

    ?STREAM_ID_BLOCKED ->
      ?DBG("Stream ID Blocked.~n", []),
      {Stream_ID, Rest1} = parse_var_length(Rest),
      {{stream_id_blocked, Stream_ID}, Rest1};

    ?NEW_CONN_ID ->
      ?DBG("New Connection ID.~n", []),
      {Sequence, <<Length:8, Rest1/binary>>} = parse_var_length(Rest),
      <<Conn_ID:Length/unit:8, Rest2>> = Rest1,
      <<Token:128, Rest3/binary>> = Rest2,
      {{new_conn_id, Sequence, Length, Conn_ID, Token}, Rest3};

    ?STOP_SENDING ->
      ?DBG("Stop Sending.~n", []),
      {Stream_ID, Rest1} = parse_var_length(Rest),
      {App_Error, Rest2} = parse_app_error(Rest1),
      {{stop_sending, Stream_ID, App_Error}, Rest2};

    ?ACK_FRAME ->
      ?DBG("Ack Frame.~n", []),
      {Largest, Rest1} = parse_var_length(Rest),
      {Ack_Delay, Rest2} = parse_var_length(Rest1),
      {Ack_Block_Count, Rest3} = parse_var_length(Rest2),
      {Acks, Rest4} = parse_ack_blocks(Rest3, Largest, Ack_Block_Count),
      %% TODO: Change to #quic_ack_frame{} record
      {{ack_frame, Largest, Ack_Delay, Ack_Block_Count, Acks}, Rest4};

    ?PATH_CHALLENGE ->
      ?DBG("Path Challenge.~n", []),
      <<Challenge:64, Rest1/binary>> = Rest,
      {{path_challenge, Challenge}, Rest1};

    ?PATH_RESPONSE ->
      ?DBG("Path Response.~n", []),
      <<Response:64, Rest1/binary>> = Rest,
      {{path_response, Response}, Rest1};

    Other ->
      %% Since all the numbers that can fit in 4-bits occur above, this shouldn't
      %% happen.
      ?DBG("Invalid type received: ~p~n", [Other]),
      {{error, badarg}, Binary}

  end;

read_frame(<<1:4, 0:1, Off:1, Len:1, Fin:1 , Rest/binary>>) ->
  parse_stream(Rest, {Off, Len, Fin});

read_frame(Other) ->
  ?DBG("Not a proper frame type: ~p.~n", [Other]),
  {error, badarg}.

%% Fin bit is not set for stream_data.
to_frame({stream_data, {Stream_ID, Offset, Message}}) ->
  Length = byte_size(Message),
  ID_Bin = to_var_length(Stream_ID),
  case {Offset, Length} of
    {0, 0} ->
      list_to_bitstring([<<1:5>>, <<0:3>>, ID_Bin]);

    {0, _} ->
      Len_Bin = to_var_length(Length),
      list_to_bitstring([<<1:5>>, <<2:3>>, ID_Bin, Len_Bin, Message]);

    {_, 0} ->
      %% Can only happen when a stream is closing
        ?DBG("Invalid stream specification. Offset: ~p, Length:~p~n",
             [Offset, Length]),
      {error, badarg};
    
    {_, _} ->
      Len_Bin = to_var_length(Length),
      Off_Bin = to_var_length(Offset),
      list_to_bitstring([<<1:5>>, <<6:3>>, ID_Bin, Off_Bin, Len_Bin, Message])
    end;

%% Fin bit is set for stream_close.
to_frame({stream_close, {Stream_ID, Offset, Message}}) ->
  Length = byte_size(Message),
  ID_Bin = to_var_length(Stream_ID),
  case {Offset, Length} of
    {0, 0} ->
      list_to_bitstring([<<1:5>>, <<1:3>>, ID_Bin]);

    {0, _} ->
      Len_Bin = to_var_length(Length),
      list_to_bitstring([<<1:5>>, <<3:3>>, ID_Bin, Len_Bin, Message]);

    {_, 0} ->
      Off_Bin = to_var_length(Offset),
      list_to_bitstring([<<1:5>>, <<5:3>>, ID_Bin, Off_Bin, Message]);
    
    {_, _} ->
      Len_Bin = to_var_length(Length),
      Off_Bin = to_var_length(Offset),
      list_to_bitstring([<<1:5>>, <<7:3>>, ID_Bin, Off_Bin, Len_Bin, Message])
    end;

to_frame(padding) ->
  <<?PADDING:8>>;

to_frame({rst_stream, Stream_ID, App_Error, Offset}) ->
  ID_Bin = to_var_length(Stream_ID),
  Off_Bin = to_var_length(Offset),
  Err_Bin = to_app_error(App_Error),
  list_to_bitstring([<<?RST_STREAM:8>>, ID_Bin, Err_Bin, Off_Bin]);

to_frame({conn_close, Conn_Error, Reason}) ->
  Err_Bin = to_conn_error(Conn_Error),
  Len_Bin = to_var_length(byte_size(Reason)),
  list_to_bitstring([<<?CONN_CLOSE:8>>, Err_Bin, Len_Bin, Reason]);

to_frame({app_close, App_Error, Reason}) ->
  Err_Bin = to_app_error(App_Error),
  Len_Bin = to_var_length(byte_size(Reason)),
  list_to_bitstring([<<?APP_CLOSE:8>>, Err_Bin, Len_Bin, Reason]);

to_frame({max_data, Max_Data}) ->
  Data_Bin = to_var_length(Max_Data),
  list_to_bitstring([<<?MAX_DATA:8>>, Data_Bin]);

to_frame({max_stream_data, Stream_ID, Max_Data}) ->
  ID_Bin = to_var_length(Stream_ID),
  Data_Bin = to_var_length(Max_Data),
  list_to_bitstring([<<?MAX_STREAM_DATA:8>>, ID_Bin, Data_Bin]);

to_frame({max_stream_id, Stream_ID}) ->
  ID_Bin = to_var_length(Stream_ID),
  list_to_bitstring([<<?MAX_STREAM_ID:8>>, ID_Bin]);

to_frame(ping) ->
  <<?PING:8>>;

to_frame({blocked, Offset}) ->
  Off_Bin = to_var_length(Offset),
  list_to_bitstring([<<?BLOCKED:8>>, Off_Bin]);

to_frame({stream_blocked, Stream_ID, Offset}) ->
  ID_Bin = to_var_length(Stream_ID),
  Off_Bin = to_var_length(Offset),
  list_to_bitstring([<<?STREAM_BLOCKED:8>>, ID_Bin, Off_Bin]);

to_frame({stream_id_blocked, Stream_ID}) ->
  ID_Bin = to_var_length(Stream_ID),
  list_to_bitstring([<<?STREAM_ID_BLOCKED:8>>, ID_Bin]);

to_frame({new_conn_id, Sequence, Length, Conn_ID, Token}) ->
  Seq_Bin = to_var_length(Sequence),
  list_to_bitstring([<<?NEW_CONN_ID:8>>, Seq_Bin, <<Length:8>>,
                     <<Conn_ID:Length/unit:8>>, <<Token:128>>]);

to_frame({stop_sending, Stream_ID, App_Error}) ->
  ID_Bin = to_var_length(Stream_ID),
  Err_Bin = to_app_error(App_Error),
  list_to_bitstring([<<?STOP_SENDING:8>>, ID_Bin, Err_Bin]);

to_frame({ack_frame, Largest, Ack_Delay, Ack_Block_Count, Acks}) ->
  Largest_Bin = to_var_length(Largest),
  Delay_Bin = to_var_length(Ack_Delay),
  Count_Bin = to_var_length(Ack_Block_Count),
  Ack_Bin = to_ack_block(Largest, Acks),
  list_to_bitstring([<<?ACK_FRAME:8>>, Largest_Bin, Delay_Bin, Count_Bin,
                     Ack_Bin]);

to_frame({path_challenge, Challenge}) ->
  list_to_bitstring([<<?PATH_CHALLENGE:8>>, <<Challenge:64>>]);

to_frame({path_response, Challenge}) ->
  list_to_bitstring([<<?PATH_RESPONSE:8>>, <<Challenge:64>>]);

to_frame(Other) ->
  ?DBG("Invalid frame type ~p~n", [Other]),
  {error, badarg}.

  
  
%%%===================================================================
%%% Internal functions
%%%===================================================================


parse_var_length(<<0:1, 0:1, Integer:6, Rest/binary>>) ->
  {Integer, Rest};
parse_var_length(<<0:1, 1:1, Integer:14, Rest/binary>>) ->
  {Integer, Rest};
parse_var_length(<<1:1, 0:1, Integer:30, Rest/binary>>) ->
  {Integer, Rest};
parse_var_length(<<1:1, 1:1, Integer:62, Rest/binary>>) ->
  {Integer, Rest};
parse_var_length(Other) ->
  ?DBG("Incorrect variable length encoded integer: ~p~n", [Other]),
  {error, badarg}.


to_var_length(Integer) when Integer < 64 ->
  list_to_bitstring([<<0:2>>, <<Integer:6>>]);

to_var_length(Integer) when Integer < 16384 ->
  list_to_bitstring([<<1:2>>, <<Integer:14>>]);

to_var_length(Integer) when Integer < 1073741824 ->
  list_to_bitstring([<<2:2>>, <<Integer:30>>]);

to_var_length(Integer) ->
  list_to_bitstring([<<3:2>>, <<Integer:62>>]).



parse_app_error(<<?STOPPING:16, Rest/binary>>) ->
  {stopping, Rest};
parse_app_error(<<App_Error:16, Rest/binary>>) ->
  {App_Error, Rest};
parse_app_error(Other) ->
  ?DBG("Error parsing application error: ~p~n", [Other]),
  {error, badarg}.


to_app_error(stopping) ->
  <<?STOPPING:16>>;
to_app_error(Other) ->
  ?DBG("App error not implemented: ~p~n", [Other]).


parse_conn_error(<<?NO_ERROR:16, Rest/binary>>) ->
  {ok, Rest};
parse_conn_error(<<?INTERNAL_ERROR:16, Rest/binary>>) ->
  {{error, internal}, Rest};
parse_conn_error(<<?SERVER_BUSY:16, Rest/binary>>) ->
  {{error, server_busy}, Rest};
parse_conn_error(<<?FLOW_CONTROL_ERROR:16, Rest/binary>>) ->
  {{error, flow_control}, Rest};
parse_conn_error(<<?STREAM_ID_ERROR:16, Rest/binary>>) ->
  {{error, stream_id}, Rest};
parse_conn_error(<<?STREAM_STATE_ERROR:16, Rest/binary>>) ->
  {{error, stream_state}, Rest};
parse_conn_error(<<?FINAL_OFFSET_ERROR:16, Rest/binary>>) ->
  {{error, final_offset}, Rest};
parse_conn_error(<<?FRAME_FORMAT_ERROR:16, Rest/binary>>) ->
  {{error, frame_format}, Rest};
parse_conn_error(<<?TRANSPORT_PARAMETER_ERROR:16, Rest/binary>>) ->
  {{error, transport_param}, Rest};
parse_conn_error(<<?VERSION_NEGOTIATION_ERROR:16, Rest/binary>>) ->
  {{error, version_neg_error}, Rest};
parse_conn_error(<<?PROTOCOL_VIOLATION:16, Rest/binary>>) ->
  {{error, protocol_violation}, Rest};
parse_conn_error(<<?UNSOLICITED_PATH_RESPONSE:16, Rest/binary>>) ->
  {{error, path_response}, Rest};
parse_conn_error(<<Frame_Error:16, Rest/binary>>) when 
    Frame_Error >= 100, Frame_Error =< 123 ->
  {{error, frame_error}, Rest};
%% TODO: parse_frame_error(Frame_Error)
parse_conn_error(Other) ->
  ?DBG("Unsupported error: ~p~n", [Other]),
  {error, badarg}.

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


parse_message(Binary, Length) ->
  ?DBG("Parsing message of length ~p bytes.~n", [Length]),
  <<Message:Length/unit:8, Rest/binary>> = Binary,
  {Message, Rest}.


%% This parses and returns the ack ranges from smallest to largest pkt num.
%% Does not include missing acks (gaps) in the result.
parse_ack_blocks(Binary, Largest_Ack, Block_Count) ->
  ?DBG("Trying to parse ack block of size ~p~n", [Block_Count]),
  ?DBG("Largest ack: ~p~n", [Largest_Ack]),
  parse_ack_blocks(Binary, Largest_Ack, Block_Count, []).


%% When the block count is 0, there are no additional ack or gap blocks,
%% only the first ack block.
parse_ack_blocks(Binary, Largest, 0, Acks) ->
  {Ack_Block, Rest} = parse_var_length(Binary),
  ?DBG("Ack_Block parsed: ~p~n", [Ack_Block]),
  ?DBG("Largest: ~p~n", [Largest]),
  {[{Ack_Block, Largest} | Acks], Rest};

parse_ack_blocks(Binary, Largest, Block_Count, Acks) when 
    Largest < 0 ->
  ?DBG("Largest packet number less than 0, ~p~n", [Largest]),
  ?DBG("Block_Count: ~p~n", [Block_Count]),
  ?DBG("Acks: ~p~n", [Acks]),
  {{error, frame_error_ack}, Binary};

%% Base case for last Ack_Block when there are additional ack blocks.
%%parse_ack_blocks(Binary, Largest, 1, Acks) ->
%%  {Ack_Block, Rest} = parse_var_length(Binary),
%%  Ack = {Ack_Block, Largest},
%%  {[Ack | Acks], Rest};

parse_ack_blocks(Binary, Largest, Block_Count, Acks) ->
  {Ack_Block, Rest} = parse_var_length(Binary),
  {Gap_Block, Rest1} = parse_var_length(Rest),

  ?DBG("Gap_Block: ~p~n", [Gap_Block]),

  %% The Ack_Block is the range of packet numbers acknowledged in the 
  %% Ack_Block, so the Largest ack of the block needs to be kept with it.
  %% MAYBE: Change to a 3-tuple with Smallest ack as well.
  Ack = {Ack_Block, Largest},

  %% The next largest ack is the number of packets is given by:
  %% Next_Largest = Previous_Smallest - Gap - 2
  %% where, 
  %% Previous_Smallest = Largest - Ack_Block
  %% See Section 7.15.1
  Next_Largest = Largest - Ack_Block - Gap_Block,

  ?DBG("Ack_Block parsed: ~p~n", [Ack_Block]),

  parse_ack_blocks(Rest1, Next_Largest, Block_Count-1, [Ack | Acks]).

%% Build the Ack Block in the order given and returns the bitstring.
to_ack_block(Largest, [{Ack, _Largest} | Ack_Block]) ->
  Smallest = Largest - Ack,
  Ack_Bin = to_var_length(Ack),
  to_ack_blocks(Smallest, Ack_Block, [Ack_Bin]).

to_ack_blocks(Smallest, _Acks, _Ack_Block) when Smallest < 0 ->
  ?DBG("Error building ack block. Largest less than 0.~n", []),
  ?DBG("Acks left: ~p~n", [_Acks]),
  {error, badarg};

to_ack_blocks(_Smallest, [], Ack_Block) ->
  list_to_bitstring(lists:reverse(Ack_Block));

to_ack_blocks(Previous, [{Ack_Range, Next} | Rest], Ack_Block) ->
  Gap = Previous - Next,
  Gap_Bin = to_var_length(Gap),
  Smallest = Next - Ack_Range,
  Ack_Bin = to_var_length(Ack_Range),

  ?DBG("Gap: ~p, Smallest: ~p, Next: ~p~n", [Gap, Smallest, Next]),

  to_ack_blocks(Smallest, Rest, [Ack_Bin, Gap_Bin | Ack_Block]).
  


%% Stream frame parsing functions,
%% Returns:
%% {{stream_data, {Stream_ID, Offset, Message}}, Rest}
%% {{stream_close, {Stream_ID, Offset, Message}}, Rest}
%% 

%% TODO: Add potential type errors here. See Section 7.18
parse_stream(Binary, Type) ->
  {Stream_ID, Rest} = parse_var_length(Binary),
  parse_offset(Rest, Type, Stream_ID).


%% Offset of 0 means the offset is 0.
parse_offset(Binary, {0, _, _}=Type, Stream_ID) ->
  parse_length(Binary, Type, {Stream_ID, 0});

%% Offset of 1 means the frame has a variable length offset given.
parse_offset(Binary, {1, _, _}=Type, Stream_ID) ->
  {Offset, Rest} = parse_var_length(Binary),
  parse_length(Rest, Type, {Stream_ID, Offset});

parse_offset(_, Type, _) ->
  ?DBG("Invalid Offset Stream Type: ~p~n", [Type]),
  {error, stream}.

%% Len of 0 means the message is the remainder of the packet.
parse_length(Binary, {_, 0, _}=Type, {Stream_ID, Offset}) ->
  parse_fin(<<>>, Type, {Stream_ID, Offset, Binary});

%% Len of 1 means the stream has a message of variable length.
parse_length(Binary, {_, 1, _}=Type, {Stream_ID, Offset}) ->
  {Length, Rest} = parse_var_length(Binary),
  {Message, Rest1} = parse_message(Rest, Length),
  parse_fin(Rest1, Type, {Stream_ID, Offset, Message});

parse_length(_, Type, _) ->
  ?DBG("Invalid Length Stream Type: ~p~n", [Type]),
  {error, stream}.


%% Fin of 0 means the stream is still open.
parse_fin(Binary, {_, _, 0}, Stream) ->
  {{stream_data, Stream}, Binary};

%% Fin of 1 means the stream is closed.
parse_fin(Binary, {_, _, 1}, Stream) ->
  {{stream_close, Stream}, Binary};

parse_fin(_, Type, _) ->
  ?DBG("Invalid Fin Stream Type: ~p~n", [Type]),
  {error, stream}.





  
