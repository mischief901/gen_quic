-module(test).

-export([bitxor/2, get_nonce/2]).

get_nonce(Pkt_Num, PRK) ->
  %% Take the last 4 bytes of the PRK to XOR with the Pkt_Num.
  <<P1:28/unit:8, P2/binary>> = PRK,
  %% PRK should be exactly 32 bytes long.
  %% This might make more sense as a guard instead of an assert failure.
  <<P1:28/unit:8, (bitxor(<<Pkt_Num:4/unit:8>>, P2))/binary>>.



-spec bitxor(binary(), binary()) -> binary().
%% Unfortunately, the Erlang bxor function only works on integers.
bitxor(Bin1, Bin2) when is_binary(Bin1), is_binary(Bin2) ->
  bitxor(Bin1, Bin2, <<>>).


bitxor(<<>>, <<>>, Acc) -> Acc;

bitxor(<<B1:8, Rest1/binary>>, <<B2:8, Rest2/binary>>, <<Acc/binary>>) ->
  bitxor(Rest1, Rest2, <<Acc/binary, (B1 bxor B2):8>>).
