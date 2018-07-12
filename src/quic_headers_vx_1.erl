%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%% 
%%% @end
%%% Created : 18 May 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_headers_vx_1).

%% API
-export([to_type/1]).
-export([to_header/3]).
-export([new_scid/0, new_scid/1]).
-export([new_dcid/0, new_dcid/1]).
-export([new_packet_no/0]).

-include("quic_headers.hrl").
-include("quic_vx_1.hrl").


%%-compile({inline, [pkt_num_length/0]}).

%%%===================================================================
%%% API
%%%===================================================================


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

to_type({short, 1}) ->
  {ok, list_to_bitstring([<<?SHORT:1>>, <<?DEFAULT_SHORT:5>>, 
                          <<?ONEBYTE:2>>]), 1};

to_type({short, 2}) ->
  {ok, list_to_bitstring([<<?SHORT:1>>, <<?DEFAULT_SHORT:5>>, 
                          <<?TWOBYTE:2>>]), 2};

to_type({short, 4}) ->
  {ok, list_to_bitstring([<<?SHORT:1>>, <<?DEFAULT_SHORT:5>>, 
                          <<?FOURBYTE:2>>]), 4};

to_type(Other) ->
  ?DBG("Type definition ~p not found.~n", [Other]),
  {error, badarg}.


%% parse_pkt_num(<<Binary/binary>>, Other, Info) ->
%%   ?DBG("Invalid Offset: ~p~n", [Other]),
%%   ?DBG("Binary: ~p~n", [Binary]),
%%   ?DBG("Info: ~p~n", [Info]),
%%   {error, badarg}.
  

%% {Dest_Conn, Src_Conn}, Frame_Mod) ->
%%   {Payload_Length, Rest2} = quic_vxx:parse_var_length(Rest1),
%%   <<Packet_Num:32, Payload/binary>> = Rest2,
%%   {Payload, {Type, Dest_Conn, Src_Conn, Payload_Length, Packet_Num}};


      
      
  

%% Version specific header formation. Packet_Info includes current packet
%% number, size of packet, and any other version specific information.
%% Returns a Header binary.

%% Long header types.
to_header({Type, Version, DCID, SCID, Packet_Num}, Payload, Length) ->
  {ok, Type_Bin} = to_type(Type),
  DCIL = byte_size(DCID),
  SCIL = byte_size(SCID),
  ID_Lens = <<DCIL:4, SCIL:4>>,
  Payload_Len_Bin = quic_vxx:to_var_length(Length),
  {ok, list_to_bitstring([Type_Bin, Version, ID_Lens, DCID, SCID, 
                          Payload_Len_Bin, <<Packet_Num:32>>, Payload])};

%% Short header types.
to_header({Type, DCID, Packet_Number}, Payload, _Length) ->
  {ok, Type_Bin, Bytes} = 
    case pkt_num_length(Packet_Number) of
      Size when Size =:= 3 ->
        to_type({Type, 4});
      Size when Size < 5, Size > 0->
        to_type({Type, Size});
      Error ->
        ?DBG("Packet_Number is too large: ~p~nSize: ~p~n", 
             [Packet_Number, Error]),
        {error, badarg}
    end,
  {ok, list_to_bitstring([Type_Bin, DCID, <<Packet_Number:Bytes/unit:8>>, 
                          <<Payload/binary>>])};

to_header(Other, Data, Length) ->
  ?DBG("Incorrect Header information given for Data.~n", []),
  ?DBG("Given: ~p~nFor: ~p~n", [Other, Data]),
  ?DBG("Payload Length: ~p~n", [Length]),
  {error, badarg}.


pkt_num_length(Number) ->
  round(math:ceil(math:log2(Number) / 8)).


new_scid() ->
  ?DBG("Source ", []),
  {scid, new_conn_id()}.

new_scid(Length) when Length >= 4, Length =< 18 ->
  ?DBG("Source ", []),
  {scid, new_conn_id(Length)};

new_scid(Length) ->
  ?DBG("Invalid SCID length: ~p~n", [Length]),
  {error, badarg}.


new_dcid() ->
  ?DBG("Destination ", []),
  {dcid, new_conn_id()}.

new_dcid(Length) when Length >= 4, Length =< 18 ->
  ?DBG("Destination ", []),
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



