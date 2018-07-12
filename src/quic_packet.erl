%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%%
%%% @end
%%% Created : 16 May 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_packet).

%% API
-export([parse_packet/2, form_packet/2]).

-include("quic_headers.hrl").

%%%===================================================================
%%% API
%%%===================================================================

%% Checks if it is a version negotiation packet. If not, looks up version in quic_vxx
%% If supported, version module parses packet. 
%% Otherwise, returns {error, unsupported}.

%% Version Negotiation Packet is not version specific.
parse_packet(<<1:1, _Type:7, 0:32, DCIL:4, SCIL:4, 
               Dest_Conn:DCIL/unit:8, Src_Conn:SCIL/unit:8, 
               Vx_Frames/bits>>, 
             #quic_conn{
                src_conn_ID=Src,
                dest_conn_ID=Dest
               }) ->

  ?DBG("Dest_Conn: ~p~nSrc_Conn: ~p~n", [Dest_Conn, Src_Conn]),

  %% Check to make sure the Packet has the correct destination and source
  %% connection ID's before parsing otherwise signal protocol violation.
  %% Prevents a malicious user from DDOS'ing version negotiation packets.
  %% Maybe move into function header.
  case Src of
    <<Dest_Conn>> ->
      case Dest of 
        <<Src_Conn>> ->
          %% All version frames are 32 bits.
          Versions = [ Vx || <<Vx:32>> <= Vx_Frames ],
          ?DBG("Versions: ~p~n", [Versions]),

          {vx_neg, <<Dest_Conn>>, <<Src_Conn>>, Versions};

        _Other ->
          ?DBG("Connection ID's do not match:~n~p~n~p~n", 
               [Dest, <<Src_Conn>>]),
          {error, protocol_violation}
      end;

    _Other ->
      ?DBG("Connection ID's do not match:~n~p~n~p~n", 
           [Src, <<Dest_Conn>>]),
      {error, protocol_violation}
  end;

%% Long header Type. Version specific info not known.
%% Cannot be optimized since it calls out to another module.
parse_packet(<<1:1, _Type:7, Version_Bin:32, _Rest/binary>> = Packet, 
             #quic_conn{
                src_conn_ID = Src_Conn, % Could be undefined
                dest_conn_ID = Dest_Conn % Could be undefined
               }) ->

  %% Lookup version and see if supported.
  case quic_vxx:supported(Version_Bin) of
    {ok, {Module, Version}} ->
      Packet_Info = #quic_packet{
                       version = Version, 
                       long = 1,
                       src_conn_ID = Src_Conn,
                       dest_conn_ID = Dest_Conn
                      },
      %% Call the version specific module to parse the packet.
      Module:parse_packet(Packet, Packet_Info);

    {error, unsupported} ->
      %% Return with unsupported if not supported.
      {error, unsupported};

    Other ->
      ?DBG("Error checking header version: ~p~n", [Other]),
      Other
  end;

%% Short header. DCID, SCID, version, and Module are already known.
parse_packet(<<0:1, _Rest/binary>> = Packet, 
             #quic_conn{
                version_mod = Module,
                version = Vx,
                src_conn_ID = DCID,
                dest_conn_ID = SCID
               }) ->

  Packet_Info = #quic_packet{
                   version = Vx,
                   src_conn_ID_len = byte_size(SCID),
                   src_conn_ID = SCID,
                   dest_conn_ID_len = byte_size(DCID),
                   dest_conn_ID = DCID,
                   type = short,
                   long = 0
                  },

  %% Call the parser in the known version module.
  Module:parse_packet(Packet, Packet_Info);

parse_packet(Other, _Unused) ->
  ?DBG("Incorrect format: ~p~n", [Other]),
  {error, badarg}.



-spec form_packet(Type, Conn) -> Result when
    Type :: atom(),
    Conn :: record(),
    Result :: {ok, Conn, Packet} | {error, Reason},
    Packet :: binary(),
    Reason :: gen_quic:errors().

form_packet(Type, #quic_conn{version = Version} = Conn) ->
  case quic_vxx:supported(<<Version>>) of
    {ok, {Module, Version}} ->
      %% Call the version specific module to parse the packet.
      Module:form_packet(Type, Conn);

    {error, unsupported} ->
      %% Return with unsupported if not supported.
      {error, unsupported};

    Other ->
      ?DBG("Error checking header version: ~p~n", [Other]),
      Other
  end;

-spec form_packet(Type, Conn, Frames) -> Result when
    Type :: atom(),
    Conn :: record(),
    Frames :: [Frame],
    Frame :: binary() | record(),
    Result :: {ok, Conn, Packet} | {error, Reason},
    Packet :: binary(),
    Reason :: gen_quic:errors().

form_packet(Type, #quic_conn{version = Version} = Conn, Frames) ->
  case quic_vxx:supported(<<Version>>) of
    {ok, {Module, Version}} ->
      Module:form_packet(Type, Conn, Frames);

    {error, unsupported} ->
      {error, unsupported};

    Other ->
      ?DBG("Error checking header version: ~p~n", [Other]),
      Other
  end.
