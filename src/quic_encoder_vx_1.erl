%%%-------------------------------------------------------------------
%%% @author alex
%%% @copyright (C) 2018, alex
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(quic_encoder_vx_1).

%% API

-export([form_frame/1]).


-include("quic_headers.hrl").
-include("quic_vx_1.hrl").

%%%===================================================================
%%% API
%%%===================================================================

-spec form_frame(quic_frame()) -> Result when
    Result :: {ok, quic_frame()}
            | {error, Reason},
    Reason :: gen_quic:frame_error().

form_frame(#{type := padding,
             length := Length} = Frame) ->
  Binary = <<0:Length/unit:8>>,
  {ok, Frame#{binary => Binary}};

form_frame(#{type := padding} = Frame) ->
  {ok, Frame#{binary => <<0:1/unit:8>>}};

form_frame(#{type := rst_stream,
             error_code := Code
            } = Frame0) when is_integer(Code) ->
  form_frame(Frame0#{error_code := <<Code:2/unit:8>>});

form_frame(#{type := rst_stream,
             stream_id := Stream,
             error_code := Code,
             offset := Offset
            } = Frame0) when is_binary(Code) ->
  Type_Bin = type_to_bin(rst_stream),
  Stream_Bin = quic_utils:to_var_length(Stream),
  Off_Bin = quic_utils:to_var_length(Offset),
  Binary = <<Type_Bin/binary, Stream_Bin/binary, Code/binary, Off_Bin/binary>>,
  Frame = Frame0#{binary => Binary},
  {ok, Frame};

form_frame(#{type := conn_close,
             error_code := Code
            } = Frame0) when is_integer(Code) ->
  form_frame(Frame0#{error_code := <<Code:2/unit:8>>});

form_frame(#{type := conn_close,
             error_code := Code
            } = Frame0) when is_binary(Code) ->
  Frame_Type = quic_utils:to_var_length(maps:get(frame_type, Frame0, 0)),
  Type_Bin = type_to_bin(conn_close),
  Frame = case Frame0 of
            #{error_message := Message} when is_binary(Message) ->
              Mess_Length = quic_utils:to_var_length(byte_size(Message)),
              Binary = <<Type_Bin/binary, Code/binary, Frame_Type/binary, 
                         Mess_Length/binary, Message/binary>>,
              Frame0#{binary => Binary};
            #{error_message := Message} when is_list(Message) ->
              Mess_Bin = list_to_binary(Message),
              Mess_Length = quic_utils:to_var_length(byte_size(Mess_Bin)),
              Binary = <<Type_Bin/binary, Code/binary, Frame_Type/binary, 
                         Mess_Length/binary, Mess_Bin/binary>>,
              Frame0#{binary => Binary}
          end,
  {ok, Frame};

form_frame(#{type := app_close,
             error_code := Code} =Frame0) when is_integer(Code) ->
  form_frame(Frame0#{error_code := <<Code:2/unit:8>>});

form_frame(#{type := app_close,
             error_code := Code
            } = Frame0) when is_binary(Code) ->
  Type_Bin = type_to_bin(app_close),
  Frame = case Frame0 of
            #{error_message := Message} when is_binary(Message) ->
              Mess_Length = quic_utils:to_var_length(byte_size(Message)),
              Binary = <<Type_Bin/binary, Code/binary, Mess_Length/binary, Message/binary>>,
              Frame0#{binary => Binary};
            #{error_message := Message} when is_list(Message) ->
              Mess_Bin = list_to_binary(Message),
              Mess_Length = quic_utils:to_var_length(byte_size(Mess_Bin)),
              Binary = <<Type_Bin/binary, Code/binary, Mess_Length/binary, Mess_Bin/binary>>,
              Frame0#{binary => Binary}
            end,
  {ok, Frame};

form_frame(#{type := max_data,
             max_data := Max
            } = Frame0) ->
  Type_Bin = type_to_bin(max_data),
  Max_Bin = quic_utils:to_var_length(Max),
  Binary = <<Type_Bin/binary, Max_Bin/binary>>,
  Frame = Frame0#{binary => Binary,
                  retransmit => true},
  {ok, Frame};

form_frame(#{type := max_stream_data,
             stream_id := Stream,
             max_data := Max
            } = Frame0) ->
  Type_Bin = type_to_bin(max_stream_data),
  Stream_Bin = quic_utils:to_var_length(Stream),
  Max_Bin = quic_utils:to_var_length(Max),
  Binary = <<Type_Bin/binary, Stream_Bin/binary, Max_Bin/binary>>,
  Frame = Frame0#{binary => Binary,
                  retransmit => true},
  {ok, Frame};

form_frame(#{type := max_stream_id,
             max_stream_id := Max
            } = Frame0) ->
  Type_Bin = type_to_bin(max_stream_id),
  Max_Bin = quic_utils:to_var_length(Max),
  Binary = <<Type_Bin/binary, Max_Bin/binary>>,
  Frame = Frame0#{binary => Binary,
                  retransmit => true},
  {ok, Frame};

form_frame(#{type := ping
            } = Frame) ->
  Binary = type_to_bin(ping),
  {ok, Frame#{binary => Binary}};

form_frame(#{type := data_blocked,
             offset := Offset
            } = Frame0) ->
  Type_Bin = type_to_bin(data_blocked),
  Off_Bin = quic_utils:to_var_length(Offset),
  Binary = <<Type_Bin/binary, Off_Bin/binary>>,
  Frame = Frame0#{binary => Binary,
                  retransmit => true},
  {ok, Frame};

form_frame(#{type := stream_data_blocked,
             stream_id := Stream,
             offset := Offset
            } = Frame0) ->
  Type_Bin = type_to_bin(stream_data_blocked),
  Stream_Bin = quic_utils:to_var_length(Stream),
  Off_Bin = quic_utils:to_var_length(Offset),
  Binary = <<Type_Bin/binary, Stream_Bin/binary, Off_Bin/binary>>,
  Frame = Frame0#{binary => Binary,
                  retransmit => true},
  {ok, Frame};

form_frame(#{type := stream_id_blocked,
             stream_id := Max_Stream
            } = Frame0) ->
  Type_Bin = type_to_bin(stream_id_blocked),
  Stream_Bin = quic_utils:to_var_length(Max_Stream),
  Binary = <<Type_Bin/binary, Stream_Bin/binary>>,
  Frame = Frame0#{binary => Binary,
                  retransmit => true},
  {ok, Frame};

form_frame(#{type := new_conn_id,
             conn_id := New_Conn,
             sequence := Seq_Num,
             reset_token := Token
            } = Frame0) when byte_size(New_Conn) >= 4, 
                             byte_size(New_Conn) =< 18 ->
  Type_Bin = type_to_bin(new_conn_id),
  Conn_Len = quic_utils:to_conn_length(New_Conn),
  Conn_Len_Bin = <<Conn_Len:1/unit:8>>,
  Seq_Bin = quic_utils:to_var_length(Seq_Num),
  Binary = <<Type_Bin/binary, Conn_Len_Bin/binary, Seq_Bin/binary,
             New_Conn/binary, Token/binary>>,
  Frame = Frame0#{binary => Binary},
  {ok, Frame};

form_frame(#{type := retire_conn_id,
             sequence := Seq_Num
            } = Frame0) ->
  Type_Bin = type_to_bin(retire_conn_id),
  Seq_Bin = quic_utils:to_var_length(Seq_Num),
  Binary = <<Type_Bin/binary, Seq_Bin/binary>>,
  Frame = Frame0#{binary => Binary},
  {ok, Frame};

form_frame(#{type := stop_sending,
             error_code := Code
            } = Frame0) when is_integer(Code) ->
  form_frame(Frame0#{error_code := <<Code:2/unit:8>>});

form_frame(#{type := stop_sending,
             stream_id := Stream,
             error_code := Code
            } = Frame0) when is_binary(Code) ->
  Type_Bin = type_to_bin(stop_sending),
  Stream_Bin = quic_utils:to_var_length(Stream),
  Binary = <<Type_Bin/binary, Stream_Bin/binary, Code/binary>>,
  Frame = Frame0#{binary => Binary},
  {ok, Frame};


form_frame(#{type := ack_frame} = Frame0) ->
  form_ack_frame(Frame0);

form_frame(#{type := path_challenge,
             challenge := Challenge
            } = Frame0) when byte_size(Challenge) =:= 8 ->
  Type_Bin = type_to_bin(path_challenge),
  Binary = <<Type_Bin/binary, Challenge/binary>>,
  Frame = Frame0#{binary => Binary},
  {ok, Frame};

form_frame(#{type := path_response,
             challenge := Challenge
            } = Frame0) when byte_size(Challenge) =:= 8 ->
  Type_Bin = type_to_bin(path_response),
  Binary = <<Type_Bin/binary, Challenge/binary>>,
  Frame = Frame0#{binary => Binary},
  {ok, Frame};

form_frame(#{type := new_token,
             token := Token
            } = Frame0) when is_binary(Token) ->
  Type_Bin = type_to_bin(new_token),
  Token_Length = quic_utils:to_var_length(byte_size(Token)),
  Binary = <<Type_Bin/binary, Token_Length/binary, Token/binary>>,
  Frame = Frame0#{binary => Binary},
  {ok, Frame};

form_frame(#{type := stream_open} = Frame0) ->
  form_stream_frame(Frame0);

form_frame(#{type := stream_data} = Frame0) ->
  form_stream_frame(Frame0);

form_frame(#{type := stream_close} = Frame0) ->
  form_stream_frame(Frame0);

form_frame(#{type := crypto,
             offset := Offset,
             binary := Crypto_Initial
            } = Frame0) ->
  %% The Crypto_Initial binary is formed by the quic_crypto module. This wraps it in
  %% the crypto frame header.
  Type_Bin = type_to_bin(crypto),
  Offset_Bin = quic_utils:to_var_length(Offset),
  Frame_Len = quic_utils:to_var_length(byte_size(Crypto_Initial)),
  Bin_Header = <<Type_Bin/binary, Offset_Bin/binary, Frame_Len/binary>>,
  
  Frame = Frame0#{retransmit => true,
                  binary := <<Bin_Header/binary, Crypto_Initial/binary>>
                 },
  {ok, Frame};

form_frame(#{type := Type
            }) ->
  io:format(standard_error, "Invalid Frame type or parameters for frame: ~p.~n", [Type]),
  {error, badarg}.

form_ack_frame(#{type := ack_frame,
                 ack_delay := Delay,
                 acks := Acks0,
                 ecn_counts := {ECT0, ECT1, ECN_CE}
                } = Frame0) ->
  %% For ack frames that are transmitting ecn information.
  Type_Bin = type_to_bin(ack_ecn),
  ECT0_Bin = quic_utils:to_var_length(ECT0),
  ECT1_Bin = quic_utils:to_var_length(ECT1),
  ECN_CE_Bin = quic_utils:to_var_length(ECN_CE),
  ECN_Bins = <<ECT0_Bin/binary, ECT1_Bin/binary, ECN_CE_Bin/binary>>,

  [Largest | Acks] = lists:sort(Acks0),
  Largest_Bin = quic_utils:to_var_length(Largest),
  Delay_Bin = quic_utils:to_var_length(Delay),
  Header_Bin = <<Type_Bin/binary, Largest_Bin/binary, Delay_Bin/binary>>,
  form_ack_frame(Frame0, Header_Bin, Largest, Acks, ECN_Bins);
  
form_ack_frame(#{type := ack_frame,
                 ack_delay := Delay,
                 acks := Acks0
                } = Frame0) ->
  [Largest | Acks] = lists:sort(Acks0),
  Type_Bin = type_to_bin(ack),
  Largest_Bin = quic_utils:to_var_length(Largest),
  Delay_Bin = quic_utils:to_var_length(Delay),
  Header_Bin = <<Type_Bin/binary, Largest_Bin/binary, Delay_Bin/binary>>,
  form_ack_frame(Frame0, Header_Bin, Largest, Acks, <<>>).

form_ack_frame(Frame0, Head_Bin, Largest, Ack_List, Option_ECN) ->
  Ack_Block = form_ack_block(<<>>, Largest, Ack_List, 0, 0),
  Binary = <<Head_Bin/binary, Ack_Block/binary, Option_ECN/binary>>,
  Frame = Frame0#{binary => Binary},
  {ok, Frame}.

form_ack_block(Block, Largest, [Next_Ack | Rest_Acks], Block_Count, Ack_Count) when
    Largest == Next_Ack + 1 ->
  form_ack_block(Block, Next_Ack, Rest_Acks, Block_Count, Ack_Count + 1);

form_ack_block(Block0, Smallest, [Next_Ack | Rest_Acks], Block_Count, Ack_Count) ->
  Ack_Num = quic_utils:to_var_length(Ack_Count),
  Gap_Num = quic_utils:to_var_length(Smallest - Next_Ack + 1),
  Block = <<Block0/binary, Ack_Num/binary, Gap_Num/binary>>,
  form_ack_block(Block, Next_Ack, Rest_Acks, Block_Count + 1, 0);

form_ack_block(Blocks, _Smallest, [], Block_Count, Ack_Count) ->
  Ack_Num = quic_utils:to_var_length(Ack_Count),
  Block_Num = quic_utils:to_var_length(Block_Count),
  <<Block_Num/binary, Blocks/binary, Ack_Num/binary>>.

form_stream_frame(Frame) ->
  {ok, Frame}.


%% This converts all the frame types to binary except for stream frames which require
%% extra info.
type_to_bin(rst_stream) ->           <<1:8>>;
type_to_bin(conn_close) ->           <<2:8>>;
type_to_bin(app_close) ->            <<3:8>>;
type_to_bin(max_data) ->             <<4:8>>;
type_to_bin(max_stream_data) ->      <<5:8>>;
type_to_bin(max_stream_id) ->        <<6:8>>;
type_to_bin(ping) ->                 <<7:8>>;
type_to_bin(data_blocked) ->         <<8:8>>;
type_to_bin(stream_data_blocked) ->  <<9:8>>;
type_to_bin(stream_id_blocked) ->   <<10:8>>;
type_to_bin(new_conn_id) ->         <<11:8>>;
type_to_bin(retire_conn_id) ->      <<12:8>>;
type_to_bin(stop_sending) ->        <<13:8>>;
type_to_bin(path_challenge) ->      <<14:8>>;
type_to_bin(path_response) ->       <<15:8>>;
type_to_bin(new_token) ->           <<25:8>>;
type_to_bin(ack) ->                 <<26:8>>;
type_to_bin(ack_ecn) ->             <<27:8>>.



