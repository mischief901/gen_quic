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

-export([new/1]).
-export([enstage/3]).
-export([destage/1]).
%%-export([switch_mode/2]). %% Maybe not this.

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

-spec new(Packing_Priority) -> PQueues when
    Packing_Priority :: none | low | balanced | high,
    PQueues :: staging().


%% It might be wise to split it out by type and delete the unneeded
%% pack queues.
new(Type) ->
  #stage{type = Type}.


%% Currently crashes when invalid queueing operation is called.
-spec enstage(Priority_Num, Frame, Staged) -> Result when
    Priority_Num :: non_neg_integer(),
    Frame :: {Type, binary()},
    Type :: resend | packed | unpacked,
    Staged :: staging(),
    Result :: Staged. %%| {error, Reason}

enstage(P_Num, {unpacked, Frame}, 
        #stage{unpacked = QUP0,
               unpacked_len = Len,
              }=Stage) ->

  QUP = enqueue({P_Num, Frame}, QUP0),
  Stage#stage{unpacked = QUP, unpacked_len = Len+1};

enstage(P_Num, {resend, Frame}, 
        #stage{resend = QR0,
               resend_len = Len,
              }=Stage) ->
  QR = enqueue({P_Num, Frame}, QR0),
  Stage#stage{resend = QR, resend_len = Len+1};

enstage(P_Num, {packed, Frame}, Stage) ->
  pack({P_Num, Frame}, Stage).


-spec pack({P_Num, Frame}, Stage) -> Result when
    P_Num :: non_neg_integer(),
    Frame :: binary(),
    Stage :: staging(),
    Result :: staging().

pack(Item, #stage{type = low, 
                  pack1 = P1_0,
                  pack1_len = Len
                 }=Stage) ->

  P1 = enqueue(Item, P1_0),
  Stage#stage{pack1 = P1, pack1_len = Len+1};

pack({_Num, Frame} = Item, 
     #stage{type = balanced, 
            pack1 = P1_0,
            pack1_len = Len
           }=Stage) when byte_size(Frame) < ?BAL ->

  %% Smaller items are placed in pack1
  %% Larger in pack2
  P1 = enqueue(Item, P1_0),
  Stage#stage{pack1 = P1, pack1_len = Len+1};

pack(Item, #stage{type = balanced, 
                  pack2 = P2_0,
                  pack2_len = Len
                 }=Stage) ->

  %% Smaller items are placed in pack1
  %% Larger in pack2
  P2 = enqueue(Item, P2_0),
  Stage#stage{pack2 = P2, pack2_len = Len+1};

pack({_Num, Frame} = Item, 
     #stage{type = high, 
            pack1 = P1_0,
            pack1_len = Len
           }=Stage) when byte_size(Frame) < ?H1 ->
  %% Smaller items are placed in pack1
  %% Medium-Small in pack2
  %% Medium-Large in pack3
  %% Large in pack4

  P1 = enqueue(Item, P1_0),
  Stage#stage{pack1 = P1, pack1_len = Len+1};

pack({_Num, Frame} = Item, 
     #stage{type = high, 
            pack2 = P2_0,
            pack2_len = Len
           }=Stage) when byte_size(Frame) < ?H2 ->
  %% Smaller items are placed in pack1
  %% Medium-Small in pack2
  %% Medium-Large in pack3
  %% Large in pack4

  P2 = enqueue(Item, P2_0),
  Stage#stage{pack2 = P2, pack2_len = Len + 1};

pack({_Num, Frame} = Item, 
     #stage{type = high, 
            pack3 = P3_0,
            pack3_len = Len
           }=Stage) when byte_size(Frame) < ?H3 ->
  %% Smaller items are placed in pack1
  %% Medium-Small in pack2
  %% Medium-Large in pack3
  %% Large in pack4

  P3 = enqueue(Item, P3_0),
  Stage#stage{pack3 = P3, pack3_len = Len + 1};

pack(Item, #stage{type = high, 
                  pack4 = P4_0,
                  pack4_len = Len
                 }=Stage) ->
  %% Smaller items are placed in pack1
  %% Medium-Small in pack2
  %% Medium-Large in pack3
  %% Large in pack4

  P4 = enqueue(Item, P4_0),
  Stage#stage{pack4 = P4, pack4_len = Len + 1}.


-spec destage(Stage) -> Result when
    Stage :: staging(),
    Frames :: [Frame],
    Frame :: binary(),
    Size :: non_neg_integer(),
    Result :: {Stage, Frames, Size} | empty.

destage(Stage) ->
  destage(Stage, [], 0).


%% Removes frames from the queues by priority or size (described
%% at top) and returns the new stage, frames, and total byte size.
-spec destage(Stage, Frames, Size) -> Result when
    Stage :: staging(),
    Frames :: [Frame],
    Frame :: binary(),
    Size :: non_neg_integer(),
    Result :: {Stage, Frames, Size} | {Stage, empty}.

destage(#stage{resend_len = 0,
               unpacked_len = 0,
               pack1_len = 0,
               pack2_len = 0,
               pack3_len = 0,
               pack4_len = 0
              } = Stage, [], 0) ->
  %% Handle empty clause right away.
  {Stage, empty};

destage(#stage{type = none,
               resend = RQ0,
               resend_len = Len
              } = Stage, 
        Frames, Size) ->
  %% Frames and Size will be empty / 0 since no packing is
  %% performed and as such no recursion is performed.
  
  case dequeue(RQ0) of
    {empty, _} ->
      %% Nothing here so move to unpacked queue.
      destage0(Stage, Frames, Size);
    
    {{value, {_, Frame}}, RQ} ->
      %% Found something so return it.
      %% Frame is guaranteed to fit since it is the only one.
      {Stage#stage{resend = RQ, resend_len = Len - 1},
       [Frame], byte_size(Frame)}
  end;

destage(#stage{resend = RQ0,
               resend_len = Len
              } = Stage, 
        Frames, Size) ->

  case dequeue(RQ0) of
    {{value, {_, Frame}}, _RQ} when
        byte_size(Frame) + Size > ?MAX ->
      %% If the frame is too big, ignore the dequeued item/queue
      %% and try queueing packable frames.
      destage0(Stage, Frames, Size);

    {{value, {_, Frame}}, RQ} ->
      %% There is room for the frame.
      %% recurse to see if more frames can be used.
      destage(Stage#stage{resend = RQ, resend_len = Len-1},
              [Frame | Frames], Size + byte_size(Frame));

    {empty, _} ->
      %% Nothing to dequeue from the resend queue, so
      %% check other queues.
      destage0(Stage, Frames, Size)
  end.


destage0(#stage{type = low} = Stage, Frames, Size) ->
  destage_low(Stage, Frames, Size);

destage0(#stage{type = balanced} = Stage, Frames, Size) ->
  destage_balanced(Stage, Frames, Size);

destage0(#stage{type = high} = Stage, Frames, Size) ->
  destage_high(Stage, Frames, Size);

destage0(#stage{type = none} = Stage, Frames, Size) ->
  destage_none(Stage, Frames, Size).


-spec destage_none(Stage, Frames, Size) -> Result when
    Stage :: staging(),
    Frames :: [Frame],
    Frame :: binary(),
    Size :: non_neg_integer(),
    Result :: {Stage, Frames, Size}.

destage_none(#stage{unpacked = QUP0,
                    unpacked_len = Len
                   } = Stage,
             _Frames, _Size) ->

  %% No packing is performed. Just add and return.
  %% Frames and Size will be empty or 0.
  {{value, {_, Frame}}, QUP} = dequeue(QUP0),

  {Stage#stage{unpacked = QUP,unpacked_len = Len - 1},
   [Frame], byte_size(Frame)}.

%% TODO: Find a better way to program this.
-spec destage_low(Stage, Frames, Size) -> Result when
    Stage :: staging(),
    Frames :: [Frame],
    Frame :: binary(),
    Size :: non_neg_integer(),
    Result :: {Stage, Frames, Size}.

destage_low(#stage{unpacked = QUP0,
                   unpacked_len = Len1,
                   pack1 = QP1_0,
                   pack1_len = Len2} = Stage,
            []=Frames, 0=Size) ->
  %% Frames is empty, so unpacked frames are considered.
  case {dequeue(QUP0), dequeue(QP1_0)} of
    {{{value, {P1, Frame1}}, QUP},
     {{value, {P2, Frame2}}, QP1}} when P1 < P2 ->
      %% Frames exist in both. Choose the one with the lower p_num
      %% The unpacked queue has a greater priority
      if
        byte_size(Frame1) + Size < ?MAX ->
          %% The frame does fit, so choose it.
          %% See if any frames in the pack queue fit.
          destage_low(Stage#stage{unpacked = QUP,
                                  unpacked_len = Len1-1},
                      [Frame1 | Frames], Size + byte_size(Frame1));

        byte_size(Frame2) + Size < ?MAX ->
          %% The high priority doesn't fit, but the other does.
          %% See if any more frames in the pack queue fit.
          destage_low(Stage#stage{pack1 = QP1, 
                                  pack1_len = Len1-1},
                      [Frame2 | Frames], Size + byte_size(Frame2));

        true ->
          %% Neither frame fits, so return
          {Stage, Frames, Size}
      end;

    {{_, _},
     {{value, {P2, Frame2}}, QP1}} when byte_size(Frame2) + Size < ?MAX ->
      %% The unpacked queue is empty or too big and the pack frame fits.
      %% Check if any more pack frames fit.
      destage_low(Stage#stage{pack1 = QP1,
                              pack1_len = Len1-1},
                  [Frame2 | Frames], Size + byte_size(Frame2));

    {{{value, {P1, Frame1}}, QUP},
     {_, _}} when byte_size(Frame1) + Size < ?MAX ->
      %% The unpacked queue fits and the pack frame is empty.
      %% Add unpacked frame and return.
      destage_low(Stage#stage{unpacked = QUP,
                              unpacked_len = Len1 - 1},
                  [Frame1 | Frames], Size + byte_size(Frame1))
  end;

destage_low(#stage{pack1 = QP1_0,
                   pack1_len = Len} = Stage,
            Frames, Size) ->
  %% Frames is not empty so only consider packing frames.
  case dequeue(QP1_0) of
    {{value, {_, Frame}}, QP1} when byte_size(Frame) + Size < ?MAX ->
      %% There is a frame to queue and it is not too large.
      %% Add it and see if more can be added.
      destage_low(Stage#stage{pack1 = QP1,
                              pack1_len = Len-1},
                  [Frame | Frames], Size + byte_size(Frame));
    _2Big ->
      %% Either: there is a frame, but it's too big or
      %% Nothing in the packing queue so return.
      {Stage, Frames, Size}
  end.


-spec destage_balanced(Stage, Frames, Size) -> Result when
    Stage :: staging(),
    Frames :: [Frame],
    Frame :: binary(),
    Size :: non_neg_integer(),
    Result :: {Stage, Frames, Size} | {Stage, empty}.

destage_balanced(#stage{unpacked_len = Len0,
                        pack1 = QP1_0,
                        pack1_len = Len1,
                        pack2 = QP2_0,
                        pack2_len = Len2} = Stage,
                 Frames, Size) when Len0 == 0;
                                    length(Frames) /= 0 ->
  %% Either there are no unpacked frames to consider or a frame 
  %% has already been chosen so unpacked is not considered.

  case {dequeue(QP1_0), dequeue(QP2_0)} of
    {{{value, {P2, Frame2}}, QP1},
     {{value, {P3, Frame3}}, QP2}} ->
      %% Frames exist in both.
      if
        P3 < P2, byte_size(Frame3) + Size < ?MAX ->
          %% The queue larger than BAL has the highest priority.
          %% Add it if it fits and try adding more frames < BAL (pack1)
          %% until no more fit. Only one frame > BAL can be chosen.
          destage_low(Stage#stage{pack2 = QP2,
                                  pack2_len = Len2 - 1},
                      [Frame3], byte_size(Frame3));
        
        byte_size(Frame2) + Size < ?MAX ->
          %% pack2 either does not have the top priority or
          %% pack2 doesn't fit, but pack1 does.
          %% Try adding more frames < BAL (pack1) until no more fit.
          destage_low(Stage#stage{pack1 = QP1,
                                  pack1_len = Len1 - 1},
                      [Frame2 | Frames], byte_size(Frame2));

        true ->
          %% No more fit so return.
          {Stage, Frames, Size};
        end;

    {{{value, {P2, Frame2}}, QP1}, {empty, _}} when 
        byte_size(Frame2) + Size < ?MAX ->
      %% pack2 is empty, but pack1 has an item and fits.
      
      destage_low(Stage#stage{pack1=QP1,
                              pack1_len = Len1 - 1},
                  [Frame2 | Frames], Size + byte_size(Frame2));

    {{empty, _}, {{value, {P3, Frame3}}, QP2}} ->
      %% Only pack2 has frames remaining, so return.
      %% There can only be one frame from pack2.
      {Stage#stage{pack2 = QP2, pack2_len = Len2 - 1},
       [Frame3], byte_size(Frame3)};

    _ ->
      %% Both queues are now empty.
      {Stage, Frames, Size}
  end;

destage_balanced(#stage{unpacked = QUP0,
                        unpacked_len = Len0,
                        pack1 = QP1_0,
                        pack1_len = Len1,
                        pack2 = QP2_0,
                        pack2_len = Len2} = Stage,
                 [] = Frames, 0 = Size) ->
  %% Frames is empty, so unpacked frames are considered.
  {{value, {P1, Frame1}}, QUP} = dequeue(QUP0),

  case {dequeue(QP1_0), dequeue(QP2_0)} of
    {{{value, {P2, Frame2}}, QP1},
     {{value, {P3, Frame3}}, QP2}} ->
      %% Frames exist in all.
      if
        P1 < P2, P1 < P3 ->
          %% The unpacked queue has the greatest priority.
          %% Try adding more frames < BAL (pack1) until no more fit.
          destage_low(Stage#stage{unpacked = QUP,
                                  unpacked_len = Len0 - 1},
                      [Frame1], byte_size(Frame1));
        
        P3 < P1, P3 < P2 ->
          %% The queue larger than BAL has the highest priority.
          %% Add it and try adding more frames < BAL (pack1)
          %% until no more fit.
          destage_low(Stage#stage{pack2 = QP2,
                                  pack2_len = Len2 - 1},
                      [Frame3], byte_size(Frame3));
        
        P2 < P1, P2 < P3 ->
          %% The queue less than BAL has the highest priority.
          %% Add it and try adding frames from pack1 or pack2.
          destage_balanced(Stage#stage{pack1 = QP1,
                                       pack1_len = Len1 - 1},
                           [Frame2], byte_size(Frame2))
      end;
    
    {{_, _}, {empty, _}} ->
      destage_low(Stage, Frames, Size);
    
    {{empty, _}, {{value, {P3, Frame3}}, QP2}} when P1 < P3 ->
      destage_balanced(Stage#stage{unpacked = QUP,
                                   unpacked_len = Len0 - 1},
                       [Frame1], byte_size(Frame1));
    
    {{empty, _}, {{value, {P3, Frame3}}, QP2}} ->
      destage_low(Stage#stage{pack2 = QP2,
                              pack2_len = Len2 - 1},
                  [Frame3], byte_size(Frame3))
  end.


-spec destage_high(Stage, Frames, Size) -> Result when
    Stage :: staging(),
    Frames :: [Frame],
    Frame :: binary(),
    Size :: non_neg_integer(),
    Result :: {Stage, Frames, Size} | {Stage, empty}.




-spec dequeue(Queue) -> Result when
    Queue :: queue:queue(Item),
    Result :: {{value, Item}, Queue} |
              {empty, Queue},
    Item :: {P_Num, Frame},
    P_Num :: non_neg_integer(),
    Frame :: binary().

dequeue(Queue) ->
  queue:out(Queue).


-spec enqueue(Item, Queue) -> Queue when
    Item :: {P_Num, Frame},
    P_Num :: non_neg_integer(),
    Frame :: binary(),
    Queue :: queue:queue(Item).

enqueue(Item, Queue) ->
  ?MOD:in(Item, Queue).
