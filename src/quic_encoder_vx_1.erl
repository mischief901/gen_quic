%%%-------------------------------------------------------------------
%%% @author alex <>
%%% @copyright (C) 2018, alex
%%% @doc
%%%
%%% @end
%%% Created :  8 Jun 2018 by alex <>
%%%-------------------------------------------------------------------
-module(quic_encoder_vx_1).

%% API
-export([encode_packet/1]).

%-compile(inline).

-include("quic_headers.hrl").
-include("quic_vx_1.hrl").


encode_packet(Packet) ->
  encode_packet(<<>>, <<>>, Packet).

encode_packet(Header, Payload, Packet) ->
  encode_header(Header, Payload, Packet).


%% Calls the fields to add for a long header.
encode_header(Header, Payload, 
              #quic_packet{long=1}=Packet) ->
  encode_next_field(Header, Payload, Packet, long());


%% Calls the fields to add for a short header.
encode_header(Header, Payload,
              #quic_packet{long=0}=Packet) ->
  encode_next_field(Header, Payload, Packet, short()).


%% Long header fields.
long() ->
  [type, version, conn_id, payload_len, payload, pkt_num, combine].

%% Short header fields.
short() ->
  [type, conn_id, pkt_num, payload, combine].


encode_next_field(Header, Payload, Packet, [Next_Field | Fields]) ->

  ?DBG("Encoding: ~p~n", [Next_Field]),
  case Next_Field of
    type ->
      encode_type(Header, Payload, Packet, Fields);

    version ->
      encode_version(Header, Payload, Packet, Fields);

    conn_id ->
      encode_conn_id(Header, Payload, Packet, Fields);

    payload_len ->
      encode_var_length(Header, Payload, Packet, Fields, 
                        Packet#quic_packet.payload_len);

    pkt_num ->
      encode_pkt_num(Header, Payload, Packet, Fields);

    payload ->
      encode_frames(Header, Payload, Packet, Fields);

    combine ->
      {ok, <<Header/bits, Payload/bits>>, Packet};

    Other ->
      ?DBG("Invalid encoding type: ~p~n", [Other]),
      ?DBG("Packet: ~p~n", [Packet]),
      {error, internal}
  end.


%% Long headers
encode_type(Header, Payload,
            #quic_packet{long=1, type=Type}=Packet, 
            Fields) ->

  {ok, Type_Bin} = to_type(Type),    
  ?DBG("Encoding Long Type: ~p~n", [Type_Bin]),
  
  encode_next_field(<<Header, Type_Bin>>, Payload, Packet, Fields);

%% Short Header
encode_type(Header, Payload,
           #quic_packet{long=0, key_phase=Key, reserve=Res}=Packet,
            Fields) ->

  {ok, Type_Bin} = to_type({short, Key, Res}),
  ?DBG("Encoding Short Type: ~p~n", [Type_Bin]),

  encode_next_field(<<Header, Type_Bin>>, 
                    Payload, Packet, Fields);

encode_type(_Header, _Payload, Packet, _Fields) ->
  ?DBG("Invalid type encoding: ~p~n", [Packet]),
  {error, internal}.


%% Versions are 32 bits long. Only in Long headers.
encode_version(Header, Payload,
               #quic_packet{version=Version}=Packet,
               Fields) ->
  ?DBG("Encoding Version Number: ~p~n", [Version]),
  encode_next_field(<<Header/bits, Version:32>>, 
                    Payload, Packet, Fields).


%% Long headers. Both Destination and Source conn IDs and lengths.
encode_conn_id(Header, Payload, 
                #quic_packet{long=1,
                             dest_conn_ID_len = DCIL,
                             src_conn_ID_len = SCIL,
                             dest_conn_ID = DCID,
                             src_conn_ID = SCID}=Packet,
                Fields) ->

  ?DBG("Encoding both conn ids: ~n~p~n~p~n", [DCID, SCID]),
  ?DBG("Lengths: ~n~p~n~p~n", [DCIL, SCIL]),
  IDs = <<DCIL:4, SCIL:4, DCID:DCIL/unit:8, SCID:SCIL/unit:8>>,
  ?DBG("IDs: ~p~n", [IDs]),

  encode_next_field(<<Header/bits, IDs>>, Payload, Packet, Fields);

%% Short header. Only the destination connection ID, no length.
encode_conn_id(Header, Payload,
               #quic_packet{long=0,
                            dest_conn_ID = DCID,
                            dest_conn_ID_len = DCIL} = Packet,
               Fields) ->

  ?DBG("Encoding connection id: ~p~nof length: ~p~n", [DCID, DCIL]),  
  encode_next_field(<<Header/bits, DCID:DCIL/unit:8>>, 
                    Payload, Packet, Fields).


encode_pkt_num(Header, Payload,
               #quic_packet{pkt_num=Pkt_Num} = Packet, 
               Fields) ->

  ?DBG("Encoding Packet number: ~p~n", [Pkt_Num]),
  {ok, Pkt_Num_Bin} =
    if
      Pkt_Num < 128 ->
        {ok, <<0:1, Pkt_Num:7>>};
      Pkt_Num < 16384 ->
        {ok, <<2:2, Pkt_Num:14>>};
      Pkt_Num < 1073741824 ->
        {ok, <<3:2, Pkt_Num:30>>};
      true ->
        ?DBG("Packet Number is too large: ~p~n", [Pkt_Num]),
        {error, internal}
    end,

  encode_next_field(<<Header/bits, Pkt_Num_Bin>>, 
                    Payload, Packet, Fields).


encode_var_length(Header, Payload, Packet, Fields, Value) ->
  ?DBG("Encoding Variable Length Value: ~p~n", [Value]),
  {ok, Val_Bin} = to_var_length(Value),
  encode_next_field(<<Header/bits, Val_Bin>>, Payload, Packet, Fields).


%% Folds over the list of frame/stream/ack_frames and creates a single binary
%% Payload.
encode_frames(Header, Payload, 
              #quic_packet{payload=Frames, ack_frames=Ack_Frames}=Packet, 
              Fields) ->
  ?DBG("Encoding the payload: ~p~n", [Frames]),
  Frame_Bin = lists:foldl(fun encode_frame/2, Payload, Frames),
  
  ?DBG("Encoding the ack_frames: ~p~n", [Ack_Frames]),
  %% The Packet info is needed for the ack frame header, otherwise a foldl 
  %% would work well.
  Final_Payload = encode_ack_frame(Packet, Ack_Frames, Frame_Bin),

  ?DBG("Payload Encoded: ~p~n", [Final_Payload]),
  encode_next_field(Header, Final_Payload, Packet, Fields).

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% Encodes the frame into a binary and appends it to the current payload.
%% Fin bit is not set for stream_data.
encode_frame(#quic_stream{
                stream_id = Stream_ID, 
                offset = Offset, 
                data = Message,
                type = Type}, 
             Payload) ->

  Length = byte_size(Message),
  ID_Bin = to_var_length(Stream_ID),
  
  {ok, Frame} = 
    case {Offset, Length} of
      {0, 0} ->
        {ok, list_to_bitstring([<<1:5>>, <<0:3>>, ID_Bin])};

      {0, _} ->
        Len_Bin = to_var_length(Length),
        {ok, list_to_bitstring([<<1:5>>, <<2:3>>, ID_Bin, Len_Bin, Message])};

      {_, 0} ->
        %% Can only happen when a stream is closing
        ?DBG("Invalid stream specification. Offset: ~p, Length:~p~n",
             [Offset, Length]),
        {error, badarg};
    
      {_, _} ->
        Len_Bin = to_var_length(Length),
        Off_Bin = to_var_length(Offset),
        {ok, list_to_bitstring([<<1:5>>, <<6:3>>, ID_Bin, Off_Bin, Len_Bin, Message])}
    end,
  <<Payload/binary, Frame>>;

%% Fin bit is set for stream_close.
encode_frame(#quic_stream{
                stream_id = Stream_ID,
                offset = Offset,
                type = Type,
                data = Message},
             Payload) ->
  
  Length = byte_size(Message),
  ID_Bin = to_var_length(Stream_ID),
  
  {ok, Frame} = 
    case {Offset, Length} of
      {0, 0} ->
        {ok, list_to_bitstring([<<1:5>>, <<1:3>>, ID_Bin])};

      {0, _} ->
        Len_Bin = to_var_length(Length),
        {ok, list_to_bitstring([<<1:5>>, <<3:3>>, ID_Bin, Len_Bin, Message])};

      {_, 0} ->
        Off_Bin = to_var_length(Offset),
        {ok, list_to_bitstring([<<1:5>>, <<5:3>>, ID_Bin, Off_Bin, Message])};
    
      {_, _} ->
        Len_Bin = to_var_length(Length),
        Off_Bin = to_var_length(Offset),
        {ok, list_to_bitstring([<<1:5>>, <<7:3>>, ID_Bin, Off_Bin, Len_Bin, Message])}
    end,
  <<Payload/binary, Frame>>;

encode_frame(padding, Payload) ->
  <<Payload/binary, ?PADDING:8>>;

encode_frame(#quic_frame{
                type = rst_stream, 
                data = {Stream_ID, App_Error, Offset}}, 
             Payload) ->

  ID_Bin = to_var_length(Stream_ID),
  Off_Bin = to_var_length(Offset),
  Err_Bin = to_app_error(App_Error),
  Frame = list_to_bitstring([<<?RST_STREAM:8>>, ID_Bin, Err_Bin, Off_Bin]),
  
  <<Payload/binary, Frame>>;

encode_frame(#quic_frame{
                type = conn_close,
                data = {Conn_Error, Reason}}, 
             Payload) ->

  Err_Bin = to_conn_error(Conn_Error),
  Len_Bin = to_var_length(byte_size(Reason)),

  Frame = list_to_bitstring([<<?CONN_CLOSE:8>>, Err_Bin, Len_Bin, Reason]),

  <<Payload/binary, Frame>>;

encode_frame(#quic_frame{
                type = app_close, 
                data = {App_Error, Reason}},
             Payload) ->

  Err_Bin = to_app_error(App_Error),
  Len_Bin = to_var_length(byte_size(Reason)),

  Frame = list_to_bitstring([<<?APP_CLOSE:8>>, Err_Bin, Len_Bin, Reason]),
  
  <<Payload/binary, Frame>>;

encode_frame(#quic_frame{
                type = max_data, 
                data = Max_Data}, 
             Payload) ->

  Data_Bin = to_var_length(Max_Data),

  Frame = list_to_bitstring([<<?MAX_DATA:8>>, Data_Bin]),
  
  <<Payload/binary, Frame>>;

encode_frame(#quic_stream{
                stream_id = Stream_ID,
                data = max_stream_data, 
                max_data = Max_Data},
             Payload) ->

  ID_Bin = to_var_length(Stream_ID),
  Data_Bin = to_var_length(Max_Data),

  Frame = list_to_bitstring([<<?MAX_STREAM_DATA:8>>, ID_Bin, Data_Bin]),
 
  <<Payload/binary, Frame>>;

encode_frame(#quic_frame{
                type = max_stream_id, 
                data = Stream_ID}, 
             Payload) ->

  ID_Bin = to_var_length(Stream_ID),
  Frame = list_to_bitstring([<<?MAX_STREAM_ID:8>>, ID_Bin]),
  
  <<Payload/binary, Frame>>;

encode_frame(ping, Payload) ->
  <<Payload/binary, ?PING:8>>;

encode_frame(#quic_frame{
                type = blocked, 
                data = Offset}, 
             Payload) ->

  Off_Bin = to_var_length(Offset),
  Frame = list_to_bitstring([<<?BLOCKED:8>>, Off_Bin]),
  
  <<Payload/binary, Frame>>;

encode_frame(#quic_stream{
                data = stream_data_blocked, 
                stream_id = Stream_ID, 
                offset = Offset}, 
             Payload) ->

  ID_Bin = to_var_length(Stream_ID),
  Off_Bin = to_var_length(Offset),

  Frame = list_to_bitstring([<<?STREAM_BLOCKED:8>>, ID_Bin, Off_Bin]),
  
  <<Payload/binary, Frame>>;

encode_frame(#quic_frame{
                type = stream_id_blocked, 
                data = Stream_ID}, 
             Payload) ->

  ID_Bin = to_var_length(Stream_ID),

  Frame = list_to_bitstring([<<?STREAM_ID_BLOCKED:8>>, ID_Bin]),
  
  <<Payload/binary, Frame>>;

encode_frame(#quic_frame{
                type = new_conn_id, 
                data = {Sequence, Length, Conn_ID, Token}}, 
             Payload) ->

  Seq_Bin = to_var_length(Sequence),

  Frame = list_to_bitstring([<<?NEW_CONN_ID:8>>, Seq_Bin, <<Length:8>>,
                             <<Conn_ID:Length/unit:8>>, <<Token:128>>]),

  <<Payload/binary, Frame>>;

encode_frame(#quic_frame{
                type = stop_sending, 
                data = {Stream_ID, App_Error}},
             Payload) ->

  ID_Bin = to_var_length(Stream_ID),
  Err_Bin = to_app_error(App_Error),

  Frame = list_to_bitstring([<<?STOP_SENDING:8>>, ID_Bin, Err_Bin]),
  
  <<Payload/binary, Frame>>;

encode_frame(#quic_frame{
                type = path_challenge, 
                data = Challenge}, 
             Payload) ->
  
  Frame = list_to_bitstring([<<?PATH_CHALLENGE:8>>, <<Challenge:64>>]),
  
  <<Payload/binary, Frame>>;

encode_frame(#quic_frame{
                type = path_response, 
                data = Challenge},
             Payload) ->

  Frame = list_to_bitstring([<<?PATH_RESPONSE:8>>, <<Challenge:64>>]),
  
  <<Payload/binary, Frame>>;

encode_frame(Other, Payload) ->
  ?DBG("Invalid frame type ~p~n", [Other]),
  ?DBG("Payload: ~p~n", [Payload]),
  {error, badarg}.


%% Encodes the ack frame and ack block fields and appends it to the 
%% current payload.
encode_ack_frame(#quic_packet{
                    ack_frames = [#quic_acks{
                                     largest=Largest,
                                     smallest = _Smallest}
                                  | _Rest] = Acks,
                    ack_count = Ack_Block_Count,
                    ack_delay = Ack_Delay},
                 Payload) ->
  
  encode_ack_frame(Acks, Ack_Block_Count, Ack_Delay, Largest, Payload).

encode_ack_frame([], _, _, _Largest, Payload) ->
  Payload.

encode_ack_frame([#quic_acks{
                     largest=Largest,
                     smallest = _Smallest}
                  | _Rest],
                 Ack_Block_Count,
                 Ack_Delay,
                 Largest,
                 Payload) ->
  
  Largest_Bin = to_var_length(Largest),
  Delay_Bin = to_var_length(Ack_Delay),
  Count_Bin = to_var_length(Ack_Block_Count),
  Ack_Bin = to_ack_block(Largest - Smallest),

  list_to_bitstring([<<?ACK_FRAME:8>>, Largest_Bin, Delay_Bin, Count_Bin,
                     Ack_Bin]);


%% Converts the atom to the corresponding packet number.
%% Includes the type of packet (Long or Short) in the output. 
to_type(initial) ->
  {ok, list_to_bitstring([<<?LONG:1>>, <<?INITIAL:7>>])};

to_type(retry) ->
  {ok, list_to_bitstring([<<?LONG:1>>, <<?RETRY:7>>])};

to_type(handshake) ->
  {ok, list_to_bitstring([<<?LONG:1>>, <<?HANDSHAKE:7>>])};

to_type(protected) ->
  {ok, list_to_bitstring([<<?LONG:1>>, <<?PROTECTED:7>>])};

to_type({short, Key, Reserve}) ->
  {ok, list_to_bitstring([<<?SHORT:1>>, <<Key:1>>, <<1:1>>, <<1:1>>, 
                          <<0:1>>, <<Reserve:3>>])};

to_type(Other) ->
  ?DBG("Type definition ~p not found.~n", [Other]),
  {error, badarg}.


%% Chooses the smallest encoding for the given integer.
to_var_length(Integer) when Integer < 64 ->
  {ok, list_to_bitstring([<<0:2>>, <<Integer:6>>])};

to_var_length(Integer) when Integer < 16384 ->
 {ok,  list_to_bitstring([<<1:2>>, <<Integer:14>>])};

to_var_length(Integer) when Integer < 1073741824 ->
  {ok, list_to_bitstring([<<2:2>>, <<Integer:30>>])};

to_var_length(Integer) ->
  {ok, list_to_bitstring([<<3:2>>, <<Integer:62>>])}.
