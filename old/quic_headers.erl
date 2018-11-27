%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%%
%%% @end
%%% Created : 16 May 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_headers).

%% API
-export([from_header/2, to_header/2]).

-include("quic_headers.hrl").

%%%===================================================================
%%% API
%%%===================================================================

%% Parses the Packet header and returns the header info and remainder of
%% the packet as {Rest, Header_Info} or unsupported.

%% Version Negotiation Packet is not version specific.
from_header(<<1:1, _Type:7, 0:32, Rest/binary>>, _Unused) ->
  from_vx_neg(Rest);

%% Long header Type. Version specific info not known.
from_header(<<1:1, Type_Bin:7, Version_Bin:32, Rest/binary>>, Unused) ->
  case quic_vxx:supported(Version_Bin) of
    {ok, {Module, Head_Mod, Frame_Mod, Version}} ->
      Type = Module:from_type(long, <<Type_Bin:7>>),
      {Rest1, Header} = Head_Mod:from_header(Rest, Unused, Type),
      {Rest1, {Module, Version, Header}};
    {error, unsupported} ->
      {error, unsupported};
    Other ->
      ?DBG("Error checking header version: ~p~n", [Other]),
      Other
  end;

%% Short headers. Version Info and Module are already known.
from_header(<<0:1, Type_Bin:7, Rest/binary>>, {Module, Version_DCIL}) ->
  Type = Module:from_type(short, <<Type_Bin:7>>),
  Module:from_header(Rest, Version_DCIL, Type);

from_header(Other, _Unused) ->
  ?DBG("Incorrect format: ~p~n", [Other]),
  {error, badarg}.
  
  

%% TODO: Move to using #quic_conn instead of tuple.
to_header(Packet_Info, {Version_Mod, Data}) ->
  case Version_Mod:to_header(Packet_Info, Data) of
    {ok, Header} ->
      {ok, Header};
    Error ->
      ?DBG("Error forming packet header: ~p~n", [Error]),
      Error
  end.



%%%===================================================================
%%% Internal functions
%%%===================================================================

%% Move to quic_vxx.
%% Needs to_vx_neg function.
from_vx_neg(<<DCIL:4, SCIL:4, Rest/binary>>) ->
  <<Dest_Conn:DCIL/unit:8, Src_Conn:SCIL/unit:8, Versions/binary>> = Rest,
  {Versions, {vx_neg, Dest_Conn, Src_Conn}};

from_vx_neg(Other) ->
  ?DBG("Incorrect negotiation packet formation: ~p~n", [Other]),
  {error, badarg}.

