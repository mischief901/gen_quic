%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%%
%%% @end
%%% Created : 12 Oct 2018 by alex <alex@alex-Lenovo>

-module(quic_utils).

-export([packet_num_send_length/1, to_var_pkt_num/1, packet_num_untruncate/3]).
-export([to_var_length/1, from_var_length/1]).
-export([to_conn_length/1, from_conn_length/1]).
-export([binary_foldl/4]).

-include("quic_headers.hrl").


%% This might change in future versions of quic.
%% Section 4.11
-spec packet_num_send_length({Send, Recv, Largest_Acked}) -> Packet_Num_Length when
    Send :: non_neg_integer(),
    Recv :: non_neg_integer(),
    Largest_Acked :: non_neg_integer(),
    Packet_Num_Length :: non_neg_integer().
packet_num_send_length({Packet_Num, _, Last_Pkt}) when Last_Pkt - Packet_Num < 128 ->
  %% One byte needed. 128 == 1 << 7
  1;
packet_num_send_length({Packet_Num, _, Last_Pkt}) when Last_Pkt - Packet_Num < 8192 ->
  %% Two bytes needed. 8192 == 1 << 13
  2;
packet_num_send_length(_) ->
  %% Otherwise 4 bytes needed.
  4.

-spec to_var_pkt_num(non_neg_integer()) -> binary().
to_var_pkt_num(Pkt_Num) when Pkt_Num < 128 ->
  <<0:1, Pkt_Num:7>>;
to_var_pkt_num(Pkt_Num) when Pkt_Num < 8192 ->
  <<2:2, Pkt_Num:14>>;
to_var_pkt_num(Pkt_Num) ->
  <<3:2, Pkt_Num:30>>.

%% Appendix A.
-spec packet_num_untruncate({Send, Recv, Largest_Acked}, Truncated_Num, Bits) -> Packet_Num when
    Send :: non_neg_integer(),
    Recv :: non_neg_integer(),
    Largest_Acked :: non_neg_integer(),
    Truncated_Num :: non_neg_integer(),
    Bits :: non_neg_integer(),
    Packet_Num :: non_neg_integer().
packet_num_untruncate({_, Largest_Recv, _}, Truncated, Bits) ->
  Pkt_Window = 1 bsl Bits,
  Mask = Pkt_Window -1,
  Pkt_H_Win = Pkt_Window div 2,
  Candidate = ((Largest_Recv + 1) band (bnot Mask)) bor Truncated,
  check_candidate(Largest_Recv + 1, Candidate, Pkt_H_Win, Pkt_Window).


-spec check_candidate(number(), number(), number(), number()) -> number().
check_candidate(Expected, Candidate, Pkt_H_Win, Pkt_Win) when 
    Candidate =< Expected - Pkt_H_Win ->
  Candidate + Pkt_Win;
check_candidate(Expected, Candidate, Pkt_H_Win, Pkt_Win) when
    Candidate > Expected + Pkt_H_Win,
    Candidate > Pkt_Win ->
  Candidate - Pkt_Win;
check_candidate(_, Candidate, _, _) ->
  Candidate.


%% Section 4.1 QUIC Transport
%% Connection ID lengths are increased by 3 if non-zero in length.
%% Allows for an 18 octet connection id to fit into a 4 bit length.
%% Conversely, encoding the length means you decrement by 3 if non-zero in length.
%% Everything else is a failure.
-spec from_conn_length(Length) -> Length when 
    Length :: non_neg_integer().
from_conn_length(0) ->
  0;
from_conn_length(Num) ->
  Num + 3.

-spec to_conn_length(ID) -> Length when 
    ID :: binary(),
    Length :: non_neg_integer().
to_conn_length(<<>>) ->
  0;
to_conn_length(Conn_ID) when byte_size(Conn_ID) >= 4, byte_size(Conn_ID) =< 18 ->
  byte_size(Conn_ID) - 3.


%% This function is present in many places.
%% Section 7.1 of QUIC.
-spec to_var_length(Num) -> Bin when
    Num :: non_neg_integer(),
    Bin :: binary().
to_var_length(Num) when Num < 63 ->
  <<0:2, Num:6>>;
to_var_length(Num) when Num < 16383 ->
  <<1:2, Num:14>>;
to_var_length(Num) when Num < 1073741823 ->
  <<2:2, Num:30>>;
to_var_length(Num) ->
  <<3:3, Num:62>>.

-spec from_var_length(Flag) -> Bits when
    Flag :: non_neg_integer(),
    Bits :: non_neg_integer().
from_var_length(Flag) ->
  case Flag of
    0 -> 6;
    1 -> 14;
    2 -> 30;
    3 -> 62
  end.
  

%% Folds over a binary, Split bytes at a time and applies a function to the
%% Accumulator and the value of Split bytes. Acts like lists:foldl, but it needs the
%% number of bytes from the binary to use at each iteration.
%% Crashes if the size of the binary rem Split is not 0.
%% May be faster if the binary is just split into a list of values
%% and then folded over using lists:foldl.
-spec binary_foldl(function(), term(), binary(), pos_integer()) -> term().
binary_foldl(_Fun, Acc, <<>>, _) ->
  Acc;

binary_foldl(Fun, Acc, Binary, Split) ->
  <<X:Split/unit:8, Rest/binary>> = Binary,
  binary_foldl(Fun, Fun(X, Acc), Rest, Split).

