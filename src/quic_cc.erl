%%% @author alex
%%% @copyright (C) 2018, alex
%%% @doc
%%% Initializes and updates timers and congestion window when packets are sent.
%%% @end

-module(quic_cc).

-export([timer_init/1]).
-export([congestion_init/1]).
-export([start_pacing_timer/1]).
-export([packet_sent/5]).
-export([available_packet_size/1]).
-export([handle_acks/4]).
-export([queue_ack/3]).
-export([get_ack/2]).
-export([packet_lost/2]).
-export([congestion_event/2]).

-include("quic_headers.hrl").

-spec timer_init(Data) -> Data when
    Data :: quic_data().
%% Updates Data to include the initial timer parameters.
%% TODO: Add options for changing from default values and
%%       for time loss detection.
timer_init(Data) ->
  Timer = #{
            timer => erlang:start_timer(1000000000, self(), undefined), 
            %% RTO or TLP timer ref. Initialized to a timer_ref for code reuse.
            pace_time => 25, %% ms
            sent_packets => #{},
            handshake_count => 0,
            tlp_count => 0,
            max_tlp => 2,
            min_tlp_timeout => 10, %% ms
            rto_count => 0,
            min_rto_timeout => 200, %% ms
            reorder_threshold => 3,
            time_reorder_threshold => infinity,
            loss_time => 0, %% Early retransmit timeout
            initial_rtt => 100, %% ms
            smooth_rtt => 0,
            var_rtt => 0,
            min_rtt => infinity,
            max_ack_delay => 25, %% ms
            ack_delay_timeout => 25, %% ms
            largest_sent_before_rto => 0,
            largest_sent => 0,
            time_last_sent_retransmit => 0,
            time_last_send_handshake => 0
           },
  Data#{timer_info => Timer}.


-spec congestion_init(Data) -> Data when
    Data :: quic_data().
%% Updates Data to include the initial congestion control parameters.
%% TODO: Add options to change from default values.
congestion_init(Data) ->
  Max_Size = 1200,
  CC = #{
         max_datagram_size => Max_Size, %% bytes
         min_window => (2 * Max_Size), %% bytes: 2 * max_datagram_size
         congestion_window => min(10 * Max_Size, max(2 * Max_Size, 14600)), 
         %% Initial window size
         loss_reduction_factor => 0.5,
         bytes_in_flight => 0,
         end_of_recovery => 0,
         ss_threshold => infinity,
         ecn_ce_counter => {0, 0, 0},
         largest_acked_packet => 0,
         acks_to_be_sent => #{initial => {0, []},
                              handshake => {0, []},
                              application => {0, []}
                             },
         %% acks_to_be_sent is a map from pkt num level to a tuple of: 
         %% {initial ack delay, list of acks to be sent}.
         ack_delay_exp => 3
        },

  Data#{cc_info => CC}.


-spec start_pacing_timer(Data) -> Data when
    Data :: quic_data().
%% This sets up the pacing timer and saves the timer ref under 
%% #{pacing_timer => TimerRef} in the timer_info field of Data.
%% The initial pace time is equal to the max_ack_delay field but may change moving forward.
start_pacing_timer(#{
                     timer_info := #{pace_time := Timer_Length} = Time_Info0
                    } = Data0) ->
  {ok, Timer_Ref} = timer:send_interval(Timer_Length, send_packet),
  Time_Info = Time_Info0#{pacing_timer => Timer_Ref},
  Data0#{timer_info := Time_Info}.


-spec available_packet_size(Data) -> {ok, Size} when
    Data :: quic_data(),
    Size :: non_neg_integer().
%% Checks the congestion window to see if there is enough byte to send a packet of Size.
available_packet_size(#{
                        cc_info := #{
                                     bytes_in_flight := In_Flight,
                                     congestion_window := Window,
                                     max_datagram_size := Max
                                    }
                       }) when Window - In_Flight >= Max ->
  %% We can send a packet of up to max size.
  {ok, Max};

available_packet_size(#{
                        cc_info := #{
                                     bytes_in_flight := In_Flight,
                                     congestion_window := Window
                                    }
                       }) ->
  %% We can send a packet, but not of maximum packet size.
  {ok, Window - In_Flight}.


-spec packet_sent(Range, Data, Frames, Size, Pkt_Num) -> Result when
    Range :: application | handshake | initial,
    Data :: quic_data(),
    Frames :: [Frame] | ack_only | handshake,
    Frame :: quic_frame(),
    Size :: non_neg_integer(),
    Pkt_Num :: non_neg_integer(),
    Result :: {ok, Data}.

packet_sent(_, 
            #{
              cc_info := #{
                           bytes_in_flight := In_Flight0
                          } = CC0,
              timer_info := #{
                              timer := Timer_Ref0,
                              sent_packets := Sent0
                             } = Timer_Info0
             } = Data0,
            Frames, Pkt_Size, Pkt_Num) ->
  %% Cancel existing timer
  _ = erlang:cancel_timer(Timer_Ref0),

  %% Update bytes in flight
  CC = CC0#{bytes_in_flight => In_Flight0 + Pkt_Size},
  Current_Time = erlang:monotonic_time(),

  {Type, Timeout} = get_timeout(Timer_Info0),
  %% Type is either rto, tlp, or early.
  %% Associate timer with Pkt_Num for easy lookup in sent_packets when fired.
  Timer_Ref = erlang:start_timer(Timeout, self(), {Type, Pkt_Num}),

  Sent = Sent0#{Pkt_Num => {Frames, Pkt_Size, Current_Time}},

  Timer_Info = Timer_Info0#{timer := Timer_Ref,
                            sent_packets := Sent,
                            largest_sent := Pkt_Num,
                            time_last_sent_retransmit := Current_Time
                           },
  Data = Data0#{timer_info := Timer_Info,
                cc_info := CC},
  {ok, Data}.


-spec get_timeout(Timer_Info) -> Result when
    Timer_Info :: map(),
    Result :: {Type, Timeout},
    Type :: rto | early | tlp,
    Timeout :: non_neg_integer().

get_timeout(#{loss_time := 0,
              smooth_rtt := SRTT,
              var_rtt := VRTT,
              max_ack_delay := Max_Ack_Delay,
              min_tlp_timeout := Min_TLP,
              min_rto_timeout := Min_RTO,
              max_tlp := Max_TLP,
              tlp_count := TLP_Count,
              rto_count := RTO_Count
             }) when TLP_Count < Max_TLP ->
  %% Set a TLP timer.
  Timeout0 = max(SRTT + (4 * VRTT) + Max_Ack_Delay, Min_RTO) * math:pow(2, RTO_Count),
  Timeout = min(Timeout0, max(1.5 * SRTT + Max_Ack_Delay, Min_TLP)),
  {tlp, round(Timeout)};

get_timeout(#{loss_time := 0,
              smooth_rtt := SRTT,
              var_rtt := VRTT,
              max_ack_delay := Max_Ack_Delay,
              min_rto_timeout := Min_RTO,
              rto_count := RTO_Count
             }) ->
  %% Set RTO timeout
  Timeout = max(SRTT + (4 * VRTT) + Max_Ack_Delay, Min_RTO) * math:pow(2, RTO_Count),
  {rto, round(Timeout)};

get_timeout(#{loss_time := Loss_Time}) ->
  %% This might be incorrect.
  {early, Loss_Time}.


-spec handle_acks(CC_State, Data, Crypto_Range, Ack_Frame) -> Result when
    CC_State :: recovery |
                slow_start |
                avoidance |
                early_data |
                crypto,
    Data :: quic_data(),
    Crypto_Range :: initial |
                    handshake |
                    short |
                    early_data,
    Ack_Frame :: quic_frame(),
    Result :: {ok, Data} |
              {error, Reason} |
              {recovery, Data, Event} |
              {slow_start | avoidance, Data},
    Reason :: gen_quic:error(),
    Event :: {packets_lost, Pkt_Nums} |
             {ecn_event, Pkt_Num},
    Pkt_Nums :: [Pkt_Num],
    Pkt_Num :: non_neg_integer().

handle_acks(CC_State0,
            #{timer_info := #{sent_packets := Sent0,
                              smooth_rtt := SRTT0,
                              var_rtt := VRTT0,
                              min_rtt := Min_RTT0
                             } = Timer_Info0,
              cc_info := CC_Info
             } = Data0,
            Crypto_Range, 
            #{type := ack_frame,
              largest := Largest_Ack,
              acks := Acks,
              ack_delay := Delay
             } = Ack_Frame) ->
  Current = erlang:monotonic_time(),
  {SRTT, VRTT, Min_RTT} = 
    case maps:find(Largest_Ack, Sent0) of
      {ok, {_, _, Sent_Time}}  ->
        %% Update the rtt if the largest ack is new.
        update_rtt(SRTT0, VRTT0, Current - Sent_Time, Delay, Min_RTT0);
      error ->
        {SRTT0, VRTT0, Min_RTT0}
    end,
  %% Split the map into packets that still need to be acked and a map of acks to update cc.
  Sent = maps:without([Largest_Ack | Acks], Sent0),
  Recv = maps:with([Largest_Ack | Acks], Sent0),

  Timer_Info = Timer_Info0#{sent_packets := Sent,
                            smooth_rtt := SRTT,
                            var_rtt := VRTT,
                            min_rtt := Min_RTT},

  Data1 = Data0#{timer_info := Timer_Info},
  %% handle_ack_cc updates the congestion state, congestion window, and bytes in flight.
  {CC_State1, Data2} = handle_ack_cc(CC_State0, Data1, Recv),

  has_congestion_event(CC_State1, Data2, Largest_Ack, maps:get(ecn_info, Ack_Frame, none)).


-spec has_congestion_event(CC_State, Data, Pkt_Num, ECN_Info) -> Result when
    CC_State :: recovery |
                slow_start |
                avoidance |
                early_data |
                crypto,
    Data :: quic_data(),
    ECN_Info :: none |
                {ECT0, ECT1, ECN_CE},
    ECT0 :: non_neg_integer(),
    ECT1 :: non_neg_integer(),
    ECN_CE :: non_neg_integer(),
    Result :: {CC_State, Data} |
              {recovery, Data, {Event, Pkt_Num}},
    Event :: pkt_loss | ecn_event,
    Pkt_Num :: non_neg_integer().

has_congestion_event(CC_State, Data, Largest_Pkt_Num, none) ->
  %% There is no ecn info in the ack frame so check for lost packets.
  check_packet_loss(CC_State, Data, Largest_Pkt_Num);

has_congestion_event(_,
                     #{cc_info := #{ecn_ce_counter := _Total} = CC0} = Data0, 
                     Largest_Pkt_Num,
                     {ECT0, ECT1, ECN_Total}) when _Total < ECN_Total ->
  %% There is ecn info in the ack frame and the ecn count is greater
  Data = Data0#{cc_info := CC0#{ecn_ce_counter => ECN_Total}},
  {recovery, Data, {ecn_event, Largest_Pkt_Num}};

has_congestion_event(CC_State, Data, Largest_Pkt_Num, _) ->
  %% The ECN count is not greater. check for lost packets.
  check_packet_loss(CC_State, Data, Largest_Pkt_Num).


-spec check_packet_loss(State, Data, Pkt_Num) -> Result when
    State :: recovery |
             CC_State,
    CC_State :: slow_start |
                avoidance |
                early_data |
                crypto,
    Data :: quic_data(),
    Pkt_Num :: non_neg_integer(),
    Result :: {CC_State, Data} |
              {recovery, Data, {packet_loss, Pkt_Num}}.

check_packet_loss(CC_State, #{timer_info := 
                                #{sent_packets := Sent,
                                  reorder_threshold := Reorder}} = Data,
                  Largest_Pkt_Num) ->
  %% The Filter returns true when the difference in outstanding packets to largest is 
  %% more than the reordering threshold.
  Filter = fun(Key, _) -> abs(Key - Largest_Pkt_Num) > Reorder end,
  case maps:to_list(maps:filter(Filter, Sent)) of
    List when length(List) =:= 0 ->
      %% There are no lost packets
      {CC_State, Data};
    List ->
      %% There are lost packets.
      {reecovery, Data, {packet_loss, List}}
  end.


-spec handle_ack_cc(CC_State, Data, Recv) -> Result when
    CC_State :: recovery |
                slow_start |
                avoidance |
                early_data |
                crypto,
    Data :: quic_data(),
    Recv :: map(),
    Result :: {CC_State, Data}.

handle_ack_cc(CC_State, Data, Recv0) when is_map(Recv0) ->
  %% Change Recv to a list, sorted by Pkt_Num.
  Recv = lists:keysort(1, maps:to_list(Recv0)),
  handle_ack_cc(CC_State, Data, Recv, 0).


-spec handle_ack_cc(CC_State, Data, Recv, Total_Size) -> Result when
    CC_State :: recovery |
                slow_start |
                avoidance |
                early_data |
                crypto,
    Data :: quic_data(),
    Recv :: [{Pkt_Num, {Frames, Size, TimeStamp}}],
    Pkt_Num :: non_neg_integer(),
    Frames :: [quic_frame()],
    Size :: non_neg_integer(),
    TimeStamp :: non_neg_integer(),
    Total_Size :: non_neg_integer(),
    Result :: {CC_State, Data}.

handle_ack_cc(CC_State, Data0, [], Total) ->
  %% Return with the CC_State and Data. CC_State gets updated at the end of recovery or
  %% when the slow start threshold is passed.
  Data = decrease_bytes_in_flight(Data0, Total),
  {CC_State, Data};

handle_ack_cc(recovery,
              #{cc_info := #{end_of_recovery := End,
                             congestion_window := Window
                            } = CC_Info0} = Data0, 
              [{Pkt_Num, {_, Size, _}} | Rest],
              Total) when Pkt_Num > End ->
  %% End of recovery. Switch CC_State to Slow_Start.
  Data = Data0#{cc_info := CC_Info0#{end_of_recovery => infinity,
                                     congestion_window => Window + Size
                                    }},
  handle_ack_cc(slow_start, Data, Rest, Total + Size);

handle_ack_cc(recovery,
              Data,
              [{_, {_, Size, _}} | Rest],
              Total) ->
  %% Still in recovery. Decrease bytes_in_flight, but keep the congestion window the same
  handle_ack_cc(recovery, Data, Rest, Total + Size);

handle_ack_cc(slow_start,
              #{cc_info := #{ss_threshold := Threshold,
                             congestion_window := Window
                            } = CC_Info0
               } = Data0,
              [{Pkt_Num, {_, Size, _}} | Rest], Total) when Window < Threshold ->
  %% Stay in slow_start. Increase the congestion window
  Data = Data0#{cc_info := CC_Info0#{congestion_window => Window + Size}},
  handle_ack_cc(slow_start, Data, Rest, Total + Size);

handle_ack_cc(slow_start,
              #{cc_info := #{congestion_window := Window0,
                             max_datagram_size := Max} = CC_Info0
               } = Data0,
              [{Pkt_Num, {_, Size, _}} | Rest], Total) ->
  %% Transition to congestion avoidance.
  Window = Window0 + (Max * Size) / Window0,
  Data = Data0#{cc_info := CC_Info0#{congestion_window => Window}},
  handle_ack_cc(avoidance, Data, Rest, Total + Size);

handle_ack_cc(avoidance,
              #{cc_info := #{congestion_window := Window0,
                             max_datagram_size := Max
                            } = CC_Info0
               } = Data0,
              [{_, {_, Size, _}} | Rest], Total) ->
  %% Stay in congestion avoidance.
  Window = Window0 + (Max * Size) / Window0,
  Data = Data0#{cc_info := CC_Info0#{congestion_window => Window}},
  handle_ack_cc(avoidance, Data, Rest, Total + Size);

handle_ack_cc(crypto, Data, _, _) ->
  %% Crypto (handshake) packets are not congestion controlled.
  {crypto, Data};
handle_ack_cc(early_data, Data, _, _) ->
  %% This is not clearly defined in the specifications. Treat it as not congestion controlled
  {early_data, Data}.  

decrease_bytes_in_flight(#{cc_info := #{bytes_in_flight := In_Flight} = CC0} = Data0,
                         Total_Acked) ->
  Data0#{cc_info := CC0#{bytes_in_flight => In_Flight - Total_Acked}}.



update_rtt(S, V, Latest, Delay, Min_RTT) when Latest < Min_RTT ->
  update_rtt(S, V, Latest, Delay, Latest);
update_rtt(S, V, Latest, Delay, Min) when Latest - Min > Delay ->
  update_rtt(S, V, Latest - Delay, Delay, Min);
update_rtt(0, _, Latest, _, Min) -> 
  {Latest, Latest / 2, Min};
update_rtt(Smooth0, Var0, Latest, Delay, Min_RTT) ->
  Sample = abs(Smooth0 - Latest),
  Var = 3/4 * Var0 + 1/4 * Sample,
  Smooth = 7/8 * Smooth0 + 1/8 * Latest,
  {Smooth, Var, Min_RTT}.


-spec queue_ack(Data, Pkt_Type, Pkt_Num) -> Result when
    Data :: quic_data(),
    Pkt_Type :: initial |
                handshake |
                short |
                early_data,
    Pkt_Num :: non_neg_integer(),
    Result :: {ok, Data}.

queue_ack(#{cc_info := #{acks_to_be_sent := Ack_Ranges} = CC0
           } = Data0, Range0, Pkt_Num) ->
  Range = case Range0 of
            early_data -> application;
            short -> application;
            _ -> Range0
          end,
  New_Range = 
    case maps:get(Range, Ack_Ranges) of
      {_, []} ->
        %% Need to set the time to calculate the ack delay when sending.
        Current_Time = erlang:monotonic_time(),
        {Current_Time, [Pkt_Num]};
      {T, Acks} ->
        {T, [Pkt_Num | Acks]}
    end,
  CC = CC0#{acks_to_be_sent := Ack_Ranges#{Range := New_Range}},
  {ok, Data0#{cc_info := CC}};

queue_ack(Data, Pkt_Type, Pkt_Num) ->
  io:format("Unimplemented: queue_ack.~n"),
  {ok, Data}.


-spec get_ack(Range, Data) -> Result when
    Range :: initial |
             handshake |
             application,
    Data :: quic_data(),
    Result :: {ok, Data, Ack_Info},
    Ack_Info :: map().

get_ack(Range, #{cc_info := #{acks_to_be_sent := Ack_Map,
                              ack_delay_exp := Delay_Exp
                             } = CC0
                } = Data0) ->
  case maps:get(Range, Ack_Map) of
    {_, []} ->
      {ok, Data0, #{}};
    {Time, Acks} ->
      Current_Time = erlang:monotonic_time(),
      Diff = Current_Time - Time,
      Delay = round(math:fmod(Diff, Delay_Exp)),
      CC = CC0#{acks_to_be_sent := Ack_Map#{Range := {0, []}}},
      Ack_Frame = #{type => ack_frame,
                    acks => Acks,
                    ack_delay => Delay
                   },
      {ok, Data0#{cc_info := CC}, Ack_Frame}
  end;

get_ack(Type, Data) ->
  {ok, Data, #{}}.

-spec packet_lost(Data, Pkt_Nums) -> Result when
    Data :: quic_data(),
    Pkt_Nums :: [non_neg_integer()],
    Result :: {ok, Data, Frames},
    Frames :: [Frame],
    Frame :: quic_frame().

packet_lost(#{timer_info := #{sent_packets := Sent0} = Timer0} = Data0,
            Pkt_Nums) ->
  %% Get the frames to re-send and restage them for sending.
  Lost = maps:with(Pkt_Nums, Sent0),
  Sent = maps:without(Pkt_Nums, Sent0),

  Total = maps:fold(fun(_, {_, Size, _}, Acc) -> Acc + Size end, 0, Lost),

  Data1 = Data0#{timer_info := #{sent_packets => Sent}},

  Data2 = decrease_bytes_in_flight(Data1, Total),
  {ok, Data2, maps:to_list(Lost)}.


-spec congestion_event(Data, Pkt_Num) -> Result when
    Data :: quic_data(),
    Pkt_Num :: non_neg_integer(),
    Result :: {ok, Data}.

congestion_event(#{cc_info := #{congestion_window := Window0,
                                loss_factor := Loss_Factor,
                                min_window := Min_Window} = CC0} = Data0,
                 Largest_Pkt_Num) ->
  Window = if
             Window0 * Loss_Factor > Min_Window ->
               Window0 * Loss_Factor;
             true ->
               Min_Window
           end,
  Data = Data0#{cc_info := CC0#{congestion_window => Window,
                                end_of_recovery => Largest_Pkt_Num,
                                ss_threshold => Window}},
  {ok, Data}.

