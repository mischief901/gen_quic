-module(test).

-export([ack_init/0]).
-export([ack_test/2]).
-export([ack_test_first_64/0]).
-export([ack_test_random_100/0]).
-export([ack_test_odd_64/0]).
-compile([export_all]).

-record(ack, 
        {
         ack_fun,
         window_fun,
         largest_ack,
         last_window,
         ack_delay
        }).

ack_init() ->
  Ack_Fun = 
    fun(<<Window:64>>, Largest_Ack) ->
        fun(Pkt_Num) when Pkt_Num > Largest_Ack ->
            %% The given packet number is larger than the window
            %% Slide the window by bit-shifting left and
            %% adding 1.
            Pkt_Num_Diff = Pkt_Num - Largest_Ack,
            Win = (Window bsl Pkt_Num_Diff) + 1,
            <<Win:64>>;

           (Pkt_Num) when Pkt_Num == Largest_Ack ->
            %% Repeat packet number.
            %% Shouldn't happen, but easy enough clause to just
            %% return.
            <<Window:64>>;
           
           (Pkt_Num) ->
            %% Packet Number is less than the largest ack so
            %% we have to bit or the window with 1 bit shifted
            %% to the correct position.
            Pkt_Num_Diff = Largest_Ack - Pkt_Num,
            Mask = 1 bsl Pkt_Num_Diff,
            <<(Window bor Mask):64>>
        end
    end,

  %% Fixing the ack_delay_exponent at 8 for now.
  Current_Time = erlang:system_time(microseconds),
  
  #ack{
     ack_fun = Ack_Fun(<<0:64>>, 0),
     window_fun = Ack_Fun,
     largest_ack = 0,
     last_window = <<0:64>>,
     ack_delay = Current_Time
    }.

ack_test(Pkt_Num, #ack{ack_fun = Fun,
                       window_fun = Win_Fun,
                       largest_ack = Largest_Ack
                      } = Ack) when Pkt_Num > Largest_Ack ->
  Window = Fun(Pkt_Num),
  Ack_Fun = Win_Fun(Window, Pkt_Num),
  Ack#ack{
    ack_fun = Ack_Fun,
    largest_ack = Pkt_Num,
    last_window = Window};
  
ack_test(Pkt_Num, #ack{ack_fun = Fun,
                       window_fun = Win_Fun,
                       largest_ack = Largest_Ack
                      } = Ack) ->
  Window = Fun(Pkt_Num),
  Ack_Fun = Win_Fun(Window, Largest_Ack),
  Ack#ack{
    ack_fun = Ack_Fun,
    last_window = Window
   }.

to_ack_frame(#ack{
                last_window = Window0,
                largest_ack = Largest
               }) ->
  to_ack_frame(Window0, Largest).

to_ack_frame(<<0:8, Rest/binary>>, Largest) ->
  %% The leading zeros of Window can be trimmed.
  to_ack_frame(Rest, Largest);

to_ack_frame(Window, Largest) ->  
  {Block_Count, Block_List} = get_block_count(Window),
  %% Block_Count is the number of items in Block_List.
  %% If Block_Count is 0, all the bits are flipped and the
  %% First block is the only block.
  %% Otherwise, there is a gap somewhere.
  Largest_Bin = to_var_length(Largest),
  Count_Bin = to_var_length(Block_Count),
  Block_Bins = lists:map(fun to_var_length/1, Block_List),
  list_to_binary([Largest_Bin, Count_Bin | Block_Bins]).


get_block_count(<<0:1, Rest/bits>>) ->
  get_block_count(Rest);
get_block_count(<<1:1, _/bits>> = Window) ->
  get_block_count(Window, ack, 0, [-1]);
get_block_count(<<>>) ->
  {0, []}.

get_block_count(<<>>, gap, Count, [_ | List]) ->
  %% Ignore the last block if it's a gap.
  {Count, List};
get_block_count(<<>>, ack, Count, List) ->
  {Count, List};
get_block_count(<<1:1, Rest/bits>>, ack, Count, [Head | Acc]) ->
  get_block_count(Rest, ack, Count, [Head + 1 | Acc]);
get_block_count(<<0:1, Rest/bits>>, ack, Count, Acc) ->
  get_block_count(Rest, gap, Count + 1, [0 | Acc]);
get_block_count(<<1:1, Rest/bits>>, gap, Count, Acc) ->
  %% Only increment count when going into a gap
  get_block_count(Rest, ack, Count, [0 | Acc]);
get_block_count(<<0:1, Rest/bits>>, gap, Count, [Head | Acc]) ->
  get_block_count(Rest, gap, Count, [Head + 1 | Acc]).


ack_test_first_64() ->
  List = lists:seq(0, 64),
  lists:foldl(fun(Num, Ack0) ->
                  Ack = ack_test(Num, Ack0),
                  io:format("Ack_Frame for ~p: ~p~n", 
                            [Num, to_ack_frame(Ack)]),
                  Ack
              end, ack_init(), List).

ack_test_odd_64() ->
  List = [X || X <- lists:seq(0,128),
               X rem 2 == 1],
  lists:foldl(fun(Num, Ack0) ->
                  Ack = ack_test(Num, Ack0),
                  io:format("Ack_Frame for ~p: ~p~n", 
                            [Num, to_ack_frame(Ack)]),

                  Ack
              end, ack_init(), List).  

ack_test_skip_every_5() ->
  List = [X || X <- lists:seq(0,64),
               X rem 5 =/= 0],
  lists:foldl(fun(Num, Ack0) ->
                  Ack = ack_test(Num, Ack0),
                  io:format("Ack_Frame for ~p: ~p~n", 
                            [Num, to_ack_frame(Ack)]),

                  Ack
              end, ack_init(), List).  

ack_test_random_100() ->
  List = [rand:uniform(100) || _ <- lists:seq(0, 100)],
  lists:foldl(fun(Num, Ack0) ->
                  Ack = ack_test(Num, Ack0),
                  io:format("Ack_Frame for ~p: ~p~n", 
                            [Num, to_ack_frame(Ack)]),

                  Ack
              end, ack_init(), List).

to_var_length(Num) when Num =< 63 ->
  <<0:2, Num:6>>;
to_var_length(Num) when Num =< 16383 ->
  <<1:2, Num:14>>;
to_var_length(Num) when Num =< 1073741823 ->
  <<2:2, Num:30>>;
to_var_length(Num) ->
  <<3:3, Num:62>>.




