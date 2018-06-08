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
%-export([encode_packet/2]).

-include("quic_headers.hrl").
-include("quic_vx_1.hrl").

%%%===================================================================
%%% API
%%%===================================================================

%% Type spec is not done yet.
%% -spec(parse_packet(Packet, Packet_Info) -> 
%%          {ok, Packet_Info, Frame_Info} |
%%          {error, Reason} when
%%     Packet :: binary(),
%%     Packet_Info :: #quic_packet,
%%     Frame_Info :: [Frame],
%%     Frame :: #quic_frame,
%%     Reason :: quic_error().
    
parse_packet(Packet, Packet_Info) ->
  ?PARSER:parse_packet(Packet, Packet_Info).



%%%===================================================================
%%% Internal functions
%%%===================================================================


