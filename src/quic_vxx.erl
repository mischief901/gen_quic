%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%% This is a generic quic version for testing and setting the API.
%%% @end
%%% Created : 18 May 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_vxx).

%% API
-export([version/0]).
-export([from_type/1, to_type/1]).
-export([new_scid/0, new_scid/1]).
-export([new_dcid/0, new_dcid/1]).
-export([new_packet_no/0]).

-include("quic_headers.hrl").
-include("quic_vxx.hrl").

%%%===================================================================
%%% API
%%%===================================================================

version() ->
  %% 32-bits
  {version, <<?VERSION_NUMBER:32>>}.


%% Parses type information dependent on the version number.
from_type(<<?LONG:1, Type:7>>) ->
  case Type of
    ?INITIAL ->
      {long, initial};
    ?RETRY ->
      {long, retry};
    ?HANDSHAKE ->
      {long, handshake};
    ?PROTECTED ->
      {long, protected};
    ?VERSION_NEG ->
      {long, version_neg};
    Other ->
      ?DBG("Unsupported long header type received: ~p~n", [Other]),
      ?DBG("Length: ~p~n", [bit_size(Type)]),
      {error, badarg}
  end;

from_type(<<?SHORT:1, _Key:1, 1:1, 1:1, 0:1, _Reserved:1, Type:2>>) ->
  case Type of 
    ?ONEBYTE ->
      {short, small_packet_no};
    ?TWOBYTE ->
      {short, medium_packet_no};
    ?FOURBYTE ->
      {short, large_packet_no};
    Other ->
      ?DBG("Packet type not currently supported: ~p~n", [Other]),
      {error, badarg}
  end;

from_type(Other) ->
  ?DBG("Incorrect header format received: ~p~n", [Other]),
  {error, badarg}.


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
to_type(version_neg) ->
  {ok, list_to_bitstring([<<?LONG:1>>, <<?VERSION_NEG:7>>])};
to_type(small_packet_no) ->
  {ok, list_to_bitstring([<<?SHORT:1>>, <<01100:5>>, <<?ONEBYTE:2>>])};
to_type(medium_packet_no) ->
  {ok, list_to_bitstring([<<?SHORT:1>>, <<01100:5>>, <<?TWOBYTE:2>>])};
to_type(large_packet_no) ->
  {ok, list_to_bitstring([<<?SHORT:1>>, <<01100:5>>, <<?FOURBYTE:2>>])};
to_type(Other) ->
  ?DBG("Type definition ~p not found.~n", [Other]),
  {error, badarg}.


new_scid() ->
  {scid, new_conn_id()}.

new_scid(Length) when Length >= 4, Length =< 18 ->
  {scid, new_conn_id(Length)};

new_scid(Length) ->
  ?DBG("Invalid SCID length: ~p~n", [Length]),
  {error, badarg}.


new_dcid() ->
  {dcid, new_conn_id()}.

new_dcid(Length) when Length >= 4, Length =< 18 ->
  {dcid, new_conn_id(Length)};

new_dcid(Length) ->
  ?DBG("Invalid DCID length: ~p~n", [Length]),
  {error, badarg}.


new_packet_no() ->
  %% Random distribution between 0 and 2^32 - 1025 = 4294966271.
  %% Does not have to be cryptographically secure or a uniform distribution.
  Pkt_no = rand:uniform(4294966271),
  ?DBG("Initial packet number of ~p chosen.~n", [Pkt_no]),
  {pkt_no, Pkt_no}.


%%%===================================================================
%%% Internal functions
%%%===================================================================

new_conn_id() ->
  new_conn_id(?DEFAULT_CONN_ID_LENGTH).

new_conn_id(Length) ->
  ID = crypto:strong_rand_bytes(Length),
  ?DBG("ID of byte size ~p generated: ~p~n", [Length, ID]),
  ID.
  
  

