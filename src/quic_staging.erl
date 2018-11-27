%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%% A fairly standard bin packing/knapsack problem approach for 
%%% packing frames together and reducing network load. This approach
%%% makes the assumption that the queues are not starved and
%%% prioritizes faster choices over space savings. Different ranges
%%% may make sense after testing for the packed queues.
%%%
%%% An "unpacked" queue is maintained for independent frames to 
%%% prevent head of line blocking resulting from lost packets.
%%% Frames from the "unpacked" queue are not packed with any other 
%%% frames from the "unpacked" queue or the "re-send" queue. 
%%% They can be packed with frames from the "packed" queue(s).
%%%
%%% A high priority "re-send" queue is the set of all frames sent
%%% but not ack'ed. The "re-send" queue is always depleted before
%%% any other queue is considered. The "re-send" queue frames can be
%%% packed with frames from the "packed" queue(s), but not from the
%%% "unpacked" queue. (This might work better as a max-heap by size
%%% instead of a FIFO queue since every item in this queue is of 
%%% equal importance.)
%%%
%%% The "packed" queue(s) are 0, 1, 2, or 4 in number for the 'none',
%%% 'low', 'balanced', and 'high' packing priority options.
%%% For 'none', no packing is performed. For 'low', frames from
%%% the "packed" queue are combined with frames from the "packed",
%%% "unpacked", and "re-send" queues when space is available using
%%% the Fit-Next packing algorithm. For 'balanced', the frames are
%%% split by fractional size into two queues; (0 - 1/2] and 
%%% (1/2 - 1]. For 'high', the frames are split by fractional size
%%% into (0-1/3], (1/3 - 1/2], (1/2 - 2/3], and (2/3 - 1]. 
%%% In 'balanced' and 'high', the frames are taken in a Fit-First by
%%% priority then Fit-Next by size.
%%% The fractional size of the frame is the ratio of frame size to 
%%% the max packet size (1200 bytes - header size).
%%% 
%%% The packing priorities correspond to worst-case when not starved:
%%% none:       ~n * optimal
%%% low:        ~2 * optimal
%%% balanced: ~7/4 * optimal
%%% high:     ~3/2 * optimal
%%% (These are probably not accurate, since it ignores the online
%%% nature of the algorithm.)
%%%
%%% @end
%%% Created :  3 Jul 2018 by alex <alex@alex-Lenovo>

-module(quic_staging).

-export([init/2]).
-export([enstage/2]).
-export([restage/2]).
-export([destage/2]).

-export_type([staging/0]).

%% The module responsible for accessing each queue.
%% Currently using the default queue implementation in the stdlib
-define(MOD, queue).

%% The thresholds for different frame sizes for packing.
%% TODO: Get more accurate numbers.
-define(MAX, 1200).
-define(H1, 800).
-define(H2, 600).
-define(H3, 400).
-define(BAL, ?H2).

-include("quic_headers.hrl").

-record(stage, {
                type :: none | low | balanced | high,
                unpacked     = ?MOD:new(),
                unpacked_len = 0,
                resend       = ?MOD:new(), 
                resend_len   = 0,
                pack1        = ?MOD:new(),
                pack1_len    = 0,
                pack2        = ?MOD:new(), 
                pack2_len    = 0,
                pack3        = ?MOD:new(), 
                pack3_len    = 0,
                pack4        = ?MOD:new(),
                pack4_len    = 0
               }).

-opaque staging() :: #stage{}.

-spec init(Data, Packing_Priority) -> {ok, Data} when
    Data :: #quic_data{},
    Packing_Priority :: none | low | balanced | high.

%% It might be wise to split it out by type and delete the unneeded
%% pack queues.
init(Data, Packing_Priority) ->
  {ok, Data#quic_data{send_queue = #stage{type = Packing_Priority}}}.


%% Currently crashes when invalid queueing operation is called.
-spec enstage(Data, Frame) -> Result when
    Data :: #quic_data{},
    Frame :: quic_frame(),
    Result :: {ok, Data}.

enstage(#quic_data{priority_num = P_Num,
                   send_queue = #stage{
                                   type = none,
                                   unpacked = QUP0,
                                   unpacked_len = Len
                                  } = Stage0
                  } = Data,
        Frame) ->
  QUP = enqueue({P_Num, Frame}, QUP0),
  {ok, Data#quic_data{priority_num = P_Num + 1,
                      send_queue = Stage0#stage{
                                     unpacked = QUP,
                                     unpacked_len = Len + 1}}};

enstage(Data, Frame) ->
  pack(Data, Frame).


-spec restage(Data, Frames) -> Result when
    Data :: #quic_data{},
    Frames :: [quic_frame()] | quic_frame(),
    Result :: {ok, Data}.

restage(#quic_data{send_queue = 
                     #stage{resend = QR0,
                            resend_len = Len
                           } = Stage
                  } = Data,
        Frames) when is_list(Frames) ->

  {QR, Num} = lists:foldl(fun(Frame, {Queue, Num}) -> 
                              {enqueue(Frame, Queue), Num + 1} end,
                          {QR0, 1}, Frames),
  
  {ok, Data#quic_data{
         send_queue = 
           Stage#stage{
             resend = QR,
             resend_len = Len + Num
            }}};

restage(#quic_data{send_queue = 
                     #stage{resend = QR0,
                            resend_len = Len
                           } = Stage
                  } = Data,
        Frame) ->
  QR = enqueue(Frame, QR0),
  {ok, Data#quic_data{
         send_queue = Stage#stage{resend = QR,
                                  resend_len = Len + 1}}}.


-spec pack(Data, Frame) -> Result when
    Data :: #quic_data{},
    Frame :: quic_frame(),
    Result :: {ok, Data}.

pack(#quic_data{priority_num = P_Num,
                send_queue = #stage{type = low,
                                    pack1 = P1_0,
                                    pack1_len = Len
                                   } = Stage0
               } = Data0,
     Frame) ->
  P1 = enqueue({P_Num, Frame}, P1_0),
  Data = Data0#quic_data{
           priority_num = P_Num + 1,
           send_queue = Stage0#stage{pack1 = P1, 
                                     pack1_len = Len + 1}},
  {ok, Data};

pack(#quic_data{priority_num = P_Num,
                send_queue = #stage{type = balanced, 
                                    pack1 = P1_0,
                                    pack1_len = Len
                                   } = Stage0} = Data0,
     #{binary := Bin} = Frame) when byte_size(Bin) < ?BAL ->
  
  %% Smaller items are placed in pack1
  %% Larger in pack2
  P1 = enqueue({P_Num, Frame}, P1_0),
  Data = Data0#quic_data{
           priority_num = P_Num + 1,
           send_queue = Stage0#stage{pack1 = P1, pack1_len = Len + 1}},
  {ok, Data};

pack(#quic_data{priority_num = P_Num,
                send_queue = #stage{type = balanced, 
                                    pack2 = P2_0,
                                    pack2_len = Len
                                   } = Stage0
               } = Data0,
     Frame) ->

  %% Smaller items are placed in pack1
  %% Larger in pack2
  P2 = enqueue({P_Num, Frame}, P2_0),
  Data = Data0#quic_data{
           priority_num = P_Num + 1,
           send_queue = Stage0#stage{pack2 = P2, pack2_len = Len+1}},
  {ok, Data};

pack(#quic_data{priority_num = P_Num,
                send_queue = #stage{type = high,
                                    pack1 = P1_0,
                                    pack1_len = Len} = Stage0
               } = Data0,
     #{binary := Bin} = Frame) when byte_size(Bin) < ?H1 ->
  %% Smaller items are placed in pack1
  %% Medium-Small in pack2
  %% Medium-Large in pack3
  %% Large in pack4

  P1 = enqueue({P_Num, Frame}, P1_0),
  Data = Data0#quic_data{priority_num = P_Num + 1,
                         send_queue = Stage0#stage{pack1 = P1, pack1_len = Len+1}},
  {ok, Data};

pack(#quic_data{priority_num = P_Num,
                send_queue = 
                  #stage{type = high, 
                         pack2 = P2_0,
                         pack2_len = Len
                        } = Stage0
               } = Data0,
     #{binary := Bin} = Frame) when byte_size(Bin) < ?H2 ->
  %% Smaller items are placed in pack1
  %% Medium-Small in pack2
  %% Medium-Large in pack3
  %% Large in pack4

  P2 = enqueue({P_Num, Frame}, P2_0),
  Data = Data0#quic_data{priority_num = P_Num + 1,
                         send_queue = Stage0#stage{pack2 = P2, 
                                                   pack2_len = Len + 1}},
  {ok, Data};

pack(#quic_data{priority_num = P_Num,
                send_queue = #stage{type = high, 
                                    pack3 = P3_0,
                                    pack3_len = Len
                                   } = Stage0
               } = Data0,
     #{binary := Bin} = Frame) when byte_size(Bin) < ?H3 ->
  %% Smaller items are placed in pack1
  %% Medium-Small in pack2
  %% Medium-Large in pack3
  %% Large in pack4

  P3 = enqueue({P_Num, Frame}, P3_0),
  Data = Data0#quic_data{priority_num = P_Num + 1,
                         send_queue = Stage0#stage{pack3 = P3, 
                                                   pack3_len = Len + 1}},
  {ok, Data};

pack(#quic_data{priority_num = P_Num,
                send_queue = #stage{type = high, 
                                    pack4 = P4_0,
                                    pack4_len = Len
                                   } = Stage0
               } = Data0,
     Frame) ->
  %% Smaller items are placed in pack1
  %% Medium-Small in pack2
  %% Medium-Large in pack3
  %% Large in pack4

  P4 = enqueue({P_Num, Frame}, P4_0),
  Data = Data0#quic_data{priority_num = P_Num + 1,
                         send_queue = Stage0#stage{pack4 = P4, 
                                                   pack4_len = Len + 1}},
  {ok, Data}.

-spec destage(Data, Size) -> Result when
    Data :: #quic_data{},
    Size :: non_neg_integer(),
    Result :: {ok, Data, Frames} | empty,
    Frames :: [Frame],
    Frame :: quic_frame().

destage(Data, Max_Size) ->
  destage(Data, [], 0, Max_Size).


%% Removes frames from the queues by priority or size (described
%% at top) and returns the new data and frames.
-spec destage(Data, Frames, Size, Max_Size) -> Result when
    Data :: #quic_data{},
    Frames :: [Frame],
    Frame :: quic_frame(),
    Size :: non_neg_integer(),
    Max_Size :: non_neg_integer(),
    Result :: {ok, Data, Frames} | empty.

destage(#quic_data{send_queue = #stage{resend_len = 0,
                                       unpacked_len = 0,
                                       pack1_len = 0,
                                       pack2_len = 0,
                                       pack3_len = 0,
                                       pack4_len = 0
                                      }}, [], _, _) ->
  %% Handle empty clause right away.
  empty;

destage(#quic_data{
           send_queue =
             #stage{type = none,
                    resend = RQ0,
                    resend_len = Len
                   } = Stage
          } = Data, 
        Frames, Size, Max) ->
  %% Frames and Size will be empty / 0 since no packing is
  %% performed and as such only one packet is sent at a time.
  
  case dequeue(RQ0) of
    {{value, {_, #{binary := Bin} = Frame}}, RQ} when byte_size(Bin) =< Max ->
      {ok, 
       Data#quic_data{send_queue = Stage#stage{resend = RQ, resend_len = Len - 1}},
       [Frame]};

    _ ->
      %% Frame is too large to send for this congestion window or queue is empty 
      %% so move on to next queue.
      destage0(Data, Frames, Size, Max)
  end;

destage(#quic_data{
           send_queue = #stage{resend = RQ0,
                               resend_len = Len
                              } = Stage} = Data,
        Frames, Size, Max) ->

  case dequeue(RQ0) of
    {{value, {_, #{binary := Bin} = Frame}}, _RQ} when
        byte_size(Bin) + Size > Max ->
      %% If the frame is too big, ignore the dequeued item/queue
      %% and try queueing packable frames.
      destage0(Data, Frames, Size, Max);

    {{value, {_, #{binary := Bin} = Frame}}, RQ} ->
      %% There is room for the frame.
      %% recurse to see if more frames can be used.
      destage(Data#quic_data{send_queue = Stage#stage{resend = RQ, resend_len = Len-1}},
              [Frame | Frames], Size + byte_size(Bin), Max);

    {empty, _} ->
      %% Nothing to dequeue from the resend queue, so
      %% check other queues.
      destage0(Data, Frames, Size, Max)
  end.

destage0(#quic_data{send_queue = #stage{type = low}} = Data, 
         Frames, Size, Max) ->
  destage_low(Data, Frames, Size, Max);

destage0(#quic_data{send_queue = #stage{type = balanced}} = Data, 
         Frames, Size, Max) ->
  destage_balanced(Data, Frames, Size, Max);

destage0(#quic_data{send_queue = #stage{type = high}} = Data,
         Frames, Size, Max) ->
  destage_high(Data, Frames, Size, Max);

destage0(#quic_data{send_queue = #stage{type = none}} = Data, 
         Frames, Size, Max) ->
  destage_none(Data, Frames, Size, Max).


-spec destage_none(Data, Frames, Size, Max) -> Result when
    Data :: #quic_data{},
    Frames :: [Frame],
    Frame :: quic_frame(),
    Size :: non_neg_integer(),
    Max :: non_neg_integer(),
    Result :: {ok, Data, Frames}.

destage_none(#quic_data{send_queue = 
                          #stage{unpacked = QUP0,
                                 unpacked_len = Len
                                } = Stage} = Data,
             _Frames, _Size, Max) ->

  %% No packing is performed. Just add and return.
  %% Frames and Size will be empty or 0.
  {{value, {_, Frame}}, QUP} = dequeue(QUP0),

  {ok,
   Data#quic_data{send_queue = Stage#stage{unpacked = QUP,unpacked_len = Len - 1}},
   [Frame]}.


-spec destage_low(Data, Frames, Size, Max) -> Result when
    Data :: #quic_data{},
    Frames :: [Frame],
    Frame :: quic_frame(),
    Size :: non_neg_integer(),
    Max :: non_neg_integer(),
    Result :: {ok, Data, Frames}.

destage_low(#quic_data{send_queue = 
                         #stage{unpacked = QUP0,
                                unpacked_len = Len1,
                                pack1 = QP1_0} = Stage
                      } = Data,
            Frames, Size, Max) when Len1 > 0 ->
  case {dequeue(QUP0), dequeue(QP1_0)} of
    {{{value, {P1, #{binary := Bin1} = Frame1}}, QUP},
     {{value, {P2, #{binary := Bin2} = Frame2}}, QP1}} when P1 < P2 ->
      %% Frames exist in both. Choose the one with the lower p_num
      %% The unpacked queue has a greater priority
      if
        byte_size(Bin1) + Size < Max ->
          %% The frame does fit, so choose it.
          %% See if any frames in the pack queue fit.
          destage_low(Data#quic_data{send_queue = 
                                       Stage#stage{unpacked = QUP,
                                                   unpacked_len = Len1 - 1}},
                      [Frame1 | Frames], Size + byte_size(Bin1), Max);

        byte_size(Bin2) + Size < Max ->
          %% The high priority doesn't fit, but the other does.
          %% See if any more frames in the pack queue fit.
          destage_low(Data#quic_data{send_queue = 
                                       Stage#stage{pack1 = QP1, 
                                                   pack1_len = Len1-1}},
                      [Frame2 | Frames], Size + byte_size(Bin2), Max);

        true ->
          %% Neither frame fits, so return
          {ok, Data, Frames}
      end;

    {{_, _},
     {{value, {_P2, #{binary := Bin} = Frame2}}, QP1}} when byte_size(Bin) + Size < Max ->
      %% The unpacked queue is empty or too big and the pack frame fits.
      %% Check if any more pack frames fit.
      destage_low(Data#quic_data{send_queue = Stage#stage{pack1 = QP1,
                                                          pack1_len = Len1-1}},
                  [Frame2 | Frames], Size + byte_size(Bin), Max);

    {{{value, {_P1, #{binary := Bin} = Frame1}}, QUP},
     {_, _}} when byte_size(Bin) + Size < Max ->
      %% The unpacked queue fits and the pack frame is empty.
      %% Add unpacked frame and return.
      destage_low(Data#quic_data{send_queue = Stage#stage{unpacked = QUP,
                                                          unpacked_len = Len1 - 1}},
                                 [Frame1 | Frames], Size + byte_size(Bin), Max)
  end;

destage_low(#quic_data{send_queue = 
                         #stage{pack1 = QP1_0,
                                pack1_len = Len} = Stage
                      } = Data,
            Frames, Size, Max) ->
  %% Frames is not empty so only consider packing frames.
  case dequeue(QP1_0) of
    {{value, {_, #{binary := Bin} = Frame}}, QP1} when byte_size(Bin) + Size < Max ->
      %% There is a frame to queue and it is not too large.
      %% Add it and see if more can be added.
      destage_low(Data#quic_data{send_queue = Stage#stage{pack1 = QP1,
                                                          pack1_len = Len-1}},
                  [Frame | Frames], Size + byte_size(Bin), Max);
    _2Big ->
      %% Either: there is a frame, but it's too big or
      %% Nothing in the packing queue so return.
      {ok, Data, Frames}
  end.


-spec destage_balanced(Data, Frames, Size, Max) -> Result when
    Data :: #quic_data{},
    Frames :: [Frame],
    Frame :: quic_frame(),
    Size :: non_neg_integer(),
    Max :: non_neg_integer(),
    Result :: {ok, Data, Frames} | empty.

destage_balanced(#quic_data{
                    priority_num = P_Num,
                    send_queue = #stage{unpacked_len = Len0,
                                        pack1 = QP1_0,
                                        pack1_len = Len1,
                                        pack2 = QP2_0,
                                        pack2_len = Len2} = Stage
                   } = Data,
                 Frames, Size, Max) when Len0 == 0;
                                         length(Frames) /= 0 ->
  %% Either there are no unpacked frames to consider or a frame 
  %% has already been chosen so unpacked is not considered.

  case {dequeue(QP1_0), dequeue(QP2_0)} of
    {{{value, {P2, #{binary := Bin2} = Frame2}}, QP1},
     {{value, {P3, #{binary := Bin3} = Frame3}}, QP2}} ->
      %% Frames exist in both.
      if
        P3 < P2, byte_size(Bin3) + Size < Max ->
          %% The queue larger than BAL has the highest priority.
          %% Add it if it fits and try adding more frames < BAL (pack1)
          %% until no more fit. Only one frame > BAL can be chosen.
          destage_low(Data#quic_data{send_queue = 
                                       Stage#stage{pack2 = QP2,
                                                   pack2_len = Len2 - 1}},
                      [Frame3], byte_size(Bin3), Max);
        
        byte_size(Bin2) + Size < Max ->
          %% pack2 either does not have the top priority or
          %% pack2 doesn't fit, but pack1 does.
          %% Try adding more frames < BAL (pack1) until no more fit.
          destage_low(Data#quic_data{
                        send_queue = Stage#stage{pack1 = QP1,
                                                 pack1_len = Len1 - 1}},
                      [Frame2 | Frames], byte_size(Bin2), Max);

        true ->
          %% No more fit so return.
          {ok, Data, Frames}
        end;

    {{{value, {_P2, #{binary := Bin2} = Frame2}}, QP1}, {empty, _}} when 
        byte_size(Bin2) + Size < Max ->
      %% pack2 is empty, but pack1 has an item and fits.
      
      destage_low(Data#quic_data{
                    send_queue = Stage#stage{pack1=QP1,
                                             pack1_len = Len1 - 1}},
                  [Frame2 | Frames], Size + byte_size(Bin2), Max);

    {{empty, _}, {{value, {_P3, #{binary := Bin3} = Frame3}}, QP2}} ->
      %% Only pack2 has frames remaining, so return.
      %% There can only be one frame from pack2.
      {ok, Data#quic_data{send_queue = Stage#stage{pack2 = QP2, pack2_len = Len2 - 1}},
       [Frame3]};

    _ ->
      %% Both queues are now empty.
      {ok, Data, Frames}
  end;

destage_balanced(#quic_data{
                    send_queue = #stage{unpacked = QUP0,
                                        unpacked_len = Len0,
                                        pack1 = QP1_0,
                                        pack1_len = Len1,
                                        pack2 = QP2_0,
                                        pack2_len = Len2} = Stage
                   } = Data,
                 Frames, Size, Max) when Len0 > 0 ->
  %% Frames is empty, so unpacked frames are considered.
  {{value, {P1, #{binary := Bin1} = Frame1}}, QUP} = dequeue(QUP0),

  case {dequeue(QP1_0), dequeue(QP2_0)} of
    {{{value, {P2, #{binary := Bin2} = Frame2}}, QP1},
     {{value, {P3, #{binary := Bin3} = Frame3}}, QP2}} ->
      %% Frames exist in all.
      if
        P1 < P2, P1 < P3, byte_size(Bin1) =< Max ->
          %% The unpacked queue has the greatest priority.
          %% Try adding more frames < BAL (pack1) until no more fit.
          destage_low(Data#quic_data{
                        send_queue = Stage#stage{unpacked = QUP,
                                                 unpacked_len = Len0 - 1}},
                      [Frame1 | Frames], byte_size(Bin1) + Size, Max);
        
        P3 < P2, (P3 < P1 orelse byte_size(Bin1) > Max), byte_size(Bin3) =< Max ->
          %% The queue larger than BAL has the highest priority.
          %% Add it and try adding more frames < BAL (pack1)
          %% until no more fit.
          destage_low(Data#quic_data{
                        send_queue = Stage#stage{pack2 = QP2,
                                                 pack2_len = Len2 - 1}},
                      [Frame3 | Frames], byte_size(Bin3) + Size, Max);
        
        (P2 < P1 orelse byte_size(Bin1) > Max), (P2 < P3 orelse byte_size(Bin3) > Max) ->
          %% The queue less than BAL has the highest priority.
          %% Add it and try adding frames from pack1 or pack2.
          destage_balanced(Data#quic_data{
                             send_queue = Stage#stage{pack1 = QP1,
                                                      pack1_len = Len1 - 1}},
                           [Frame2 | Frames], byte_size(Bin2) + Size, Max)
      end;
    
    {{_, _}, {empty, _}} ->
      destage_low(Data, Frames, Size, Max);
    
    {{empty, _}, {{value, {P3, _Frame3}}, _QP2}} when P1 < P3, byte_size(Bin1) =< Max ->
      destage_balanced(Data#quic_data{
                         send_queue = Stage#stage{unpacked = QUP,
                                                  unpacked_len = Len0 - 1}},
                       [Frame1 | Frames], byte_size(Bin1) + Size, Max);
    
    {{empty, _}, {{value, {_P3, #{binary := Bin3} = Frame3}}, QP2}} when byte_size(Bin3) =< Max ->
      destage_low(Data#quic_data{
                    send_queue = Stage#stage{pack2 = QP2,
                                             pack2_len = Len2 - 1}},
                  [Frame3 | Frames], byte_size(Bin3) + Size, Max)
  end.


-spec destage_high(Data, Frames, Size, Max) -> Result when
    Data :: #quic_data{},
    Frames :: [Frame],
    Frame :: binary(),
    Size :: non_neg_integer(),
    Max :: non_neg_integer(),
    Result :: {ok, Data, Frames} | empty.

destage_high(Data, Frames, Size, Max) ->
  %% Not implemented yet. Probably not necessary.
  destage_balanced(Data, Frames, Size, Max).


-spec dequeue(Queue) -> Result when
    Queue :: ?MOD:queue(Item),
    Result :: {{value, Item}, Queue} |
              {empty, Queue},
    Item :: {P_Num, Frame} | Frame,
    P_Num :: non_neg_integer(),
    Frame :: quic_frame().

dequeue(Queue) ->
  ?MOD:out(Queue).


-spec enqueue(Item, Queue) -> Queue when
    Item :: {P_Num, Frame} | Frame,
    P_Num :: non_neg_integer(),
    Frame :: quic_frame(),
    Queue :: ?MOD:queue(Item).

enqueue(Item, Queue) ->
  ?MOD:in(Item, Queue).
