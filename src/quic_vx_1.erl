%%%-------------------------------------------------------------------
%%% @author alex
%%% @copyright (C) 2018, alex
%%% @doc
%%%  This dispatches to the version specific parser and encoder of packets.
%%% @end
%%%-------------------------------------------------------------------
-module(quic_vx_1).

%% API
-export([parse_frames/1, form_frame/1]).
-export([form_packet/3]).

-include("quic_headers.hrl").

%%%===================================================================
%%% API
%%%===================================================================

-spec parse_frames(Payload) -> Result when
    Payload :: binary(),
    Result :: {Frames, Ack_Frames, TLS_Info} |
              {error, Reason},
    Frames :: [Frame],
    Ack_Frames :: [Frame],
    Frame :: quic_frame(),
    TLS_Info :: #tls_record{},
    Reason :: gen_quic:error().

parse_frames(Payload) ->
  quic_parser_vx_1:parse_frames(Payload).


-spec form_frame(Frame_Info) -> Result when
    Frame_Info :: quic_frame(),
    Result :: {ok, quic_frame()} |
              {error, Reason},
    Reason :: gen_quic:frame_error().

form_frame(Frame_Info) ->
  quic_encoder_vx_1:form_frame(Frame_Info).


%% This needs updating. Should only form payload or header.
-spec form_packet(Type, Data, Frames) -> Result when
    Type :: initial |
            early_data |
            handshake |
            short,
    Data :: #quic_data{},
    Frames :: [Frame],
    Frame :: quic_frame(),
    Result :: {ok, Data, Header, Payload, Pkt_Num} | {error, Reason},
    Header :: binary(),
    Payload :: binary(),
    Pkt_Num :: {non_neg_integer(), binary()},
    Reason :: gen_quic:error().

form_packet(Type, Data, Frames) ->
  Payload = lists:foldl(fun(#{binary := Bin}, <<Acc/binary>>) ->
                            <<Acc/binary, Bin/binary>> end,
                        <<>>, Frames),
  form_header(Type, Data, Payload).

-spec form_header(Type, Data, Payload) -> Result when
    Type :: initial |
            early_data |
            handshake |
            short,
    Data :: #quic_data{},
    Payload :: binary(),
    Result :: {error, Reason} |
              {ok, Data, Header, Payload, Pkt_Num},
    Header :: binary(), %% Does not include the Pkt_Num.
    Pkt_Num :: {non_neg_integer(), binary()},
    Reason :: gen_quic:error().

form_header(initial,
            #quic_data{
               conn = #quic_conn{
                         src_conn_ID = Src_ID,
                         dest_conn_ID = Dest_ID
                        },
               version = #quic_version{
                            negotiated_version = Version
                           },
               pkt_nums = #{initial := {Pkt_Num, _, _} = Num_Range},
               retry_token = Retry_Token
              } = Data,
            Payload) ->

  Pkt_Num_Length = quic_utils:packet_num_send_length(Num_Range),
  Length = quic_utils:to_var_length(byte_size(Payload) + Pkt_Num_Length),
  Token_Length = quic_utils:to_var_length(byte_size(Retry_Token)),

  Pkt_Num_Bin = quic_utils:to_var_pkt_num(Pkt_Num),

  Src_Conn_Len = quic_utils:to_conn_length(Src_ID),
  Dest_Conn_Len = quic_utils:to_conn_length(Dest_ID),

  Header = <<1:1, 16#7f:7, Version/binary, Dest_Conn_Len:4, Src_Conn_Len:4,
             Dest_ID/binary, Src_ID/binary, Token_Length/binary, Retry_Token/binary, 
             Length/binary>>,
  {ok, Data, Header, Payload, {Pkt_Num, Pkt_Num_Bin}};

form_header(handshake,
            #quic_data{
               conn = #quic_conn{
                         src_conn_ID = Src_ID,
                         dest_conn_ID = Dest_ID
                        },
               version = #quic_version{
                            negotiated_version = Version
                           },
               pkt_nums = #{handshake := {Pkt_Num, _, _} = Num_Range}
              } = Data,
            Payload) ->
  Pkt_Num_Length = quic_utils:packet_num_send_length(Num_Range),
  Length = quic_utils:to_var_length(byte_size(Payload) + Pkt_Num_Length),

  Pkt_Num_Bin = quic_utils:to_var_pkt_num(Pkt_Num),

  Src_Conn_Len = quic_utils:to_conn_length(Src_ID),
  Dest_Conn_Len = quic_utils:to_conn_length(Dest_ID),

  Header = <<1:1, 16#7d:7, Version/binary, Dest_Conn_Len:4, Src_Conn_Len:4,
             Dest_ID/binary, Src_ID/binary, Length/binary>>,
  {ok, Data, Header, Payload, {Pkt_Num, Pkt_Num_Bin}};
  
form_header(early_data,
            #quic_data{
               conn = #quic_conn{
                         src_conn_ID = Src_ID,
                         dest_conn_ID = Dest_ID
                        },
               version = #quic_version{
                            negotiated_version = Version
                           },
               pkt_nums = #{protected := {Pkt_Num, _, _} = Num_Range}
              } = Data,
            Payload) ->
  Pkt_Num_Length = quic_utils:packet_num_send_length(Num_Range),
  Length = quic_utils:to_var_length(byte_size(Payload) + Pkt_Num_Length),

  Pkt_Num_Bin = quic_utils:to_var_pkt_num(Pkt_Num),

  Src_Conn_Len = quic_utils:to_conn_length(Src_ID),
  Dest_Conn_Len = quic_utils:to_conn_length(Dest_ID),

  Header = <<1:1, 16#7c:7, Version/binary, Dest_Conn_Len:4, Src_Conn_Len:4,
             Dest_ID/binary, Src_ID/binary, Length/binary>>,
  {ok, Data, Header, Payload, {Pkt_Num, Pkt_Num_Bin}};

%% TODO: Add key-phase to short packets.
form_header(short,
            #quic_data{
               conn = #quic_conn{
                         dest_conn_ID = Dest_ID
                        },
               pkt_nums = #{protected := {Pkt_Num, _, _}}
              } = Data,
            Payload) ->

  Pkt_Num_Bin = quic_utils:to_var_pkt_num(Pkt_Num),

  Header = <<0:1, 0:1, 1:1, 1:1, 0:1, 0:1, 0:1, 0:1, Dest_ID/binary>>,
  {ok, Data, Header, Payload, {Pkt_Num, Pkt_Num_Bin}}.
            

