%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%%  This dispatches to the version specific parser and encoder of packets.
%%% @end
%%% Created :  5 Jun 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_vx_1).

%% API
-export([parse_packet/2]).
-export([form_packet/2]).

-include("quic_headers.hrl").

%%%===================================================================
%%% API
%%%===================================================================

-spec parse_packet(Packet, Data) -> Result when
    Packet :: binary(),
    Data :: #quic_data{},
    Result :: {ok, Data, Frames, TLS_Info} |
              {error, Reason},
    Frames :: [Frame],
    Frame :: quic_frame(),
    TLS_Info :: #tls_record{},
    Reason :: gen_quic:quic_errors().
    
parse_packet(Packet, Data) ->
  quic_parser_vx_1:parse_packet(Packet, Data).


-spec form_packet(Type, Data) -> Result when
    Type :: retry |
            vx_neg,
    Data :: #quic_data{},
    Result :: {ok, Data, Packet} | {error, Reason},
    Packet :: binary(),
    Reason :: gen_quic:errors().
%% TODO:
form_packet(retry, Data) ->
  ok;

form_packet(vx_neg, Data) ->
  ok.


-spec form_packet(Type, Data, Frames) -> Result when
    Type :: initial |
            early_data |
            handshake |
            short,
    Data :: #quic_data{},
    Frames :: [Frame],
    Frame :: quic_frame(),
    Result :: {ok, Data, Packet} | {error, Reason},
    Packet :: binary(),
    Reason :: gen_quic:errors().
            
form_packet(Type, Data, Frames) ->
  quic_encoder_vx_1:encode_packet(Type, Data, Frames).
            

%%%===================================================================
%%% Internal functions
%%%===================================================================


