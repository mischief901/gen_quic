%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%% Probably better as a gen_statem.
%%% The quic_prim module is a gen_server for providing flow control,
%%% congestion control, and reliability over a udp socket.
%%% The gen_server is registered via the quic_registry module and
%%% creates a single interface over the socket for all quic streams.
%%% Prior to sending information packet headers (including packet 
%%% numbers) are assigned via this process. All packets are received,
%%% parsed, and acked via this process as well. This is a potential
%%% bottleneck to explore in the future.
%%%
%%% Unsent and Unacked packets are stored in a priority queue and 
%%% moved to a second priority queue after being sent, but still unacked.
%%% When the packet is acked, it is removed from the second priority queue.
%%% The priority queues are ranked by packet number. The purpose of
%%% the second queue is to reduce the impact of filtering out acks,
%%% which is O(n).
%%% @end
%%% Created : 29 Jun 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------

-module(quic_prim).

-behaviour(gen_server).

%% API
-export([open/1]).
-export([connect/3]).
-export([reconnect/3]).
-export([send/2]).
-export([close/1]).
-export([controlling_process/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3, format_status/2]).

-record(state, 
        {
         socket,
         ip_addr,
         port,
         options,
         sent,
         unsent
        }).

%%%===================================================================
%%% API
%%%===================================================================

-spec controlling_process(Socket, Pid) -> Result when
    Socket :: gen_quic:socket(),
    Pid :: pid(),
    Result :: ok | {error, Reason},
    Reason :: closed | not_owner | badarg | inet:posix().

controlling_process(Socket, Pid) ->
  inet:udp_controlling_process(Socket, Pid).


-spec open(Opts) -> Result when
    Opts :: [Opt],
    Opt :: gen_quic:option(),
    Result :: {ok, Socket} | {error, Reason},
    Socket :: gen_quic:socket(),
    Reason :: inet:posix().

open(Opts) when is_list(Opts) ->
  {ok, Socket} = inet_udp:open(0, Opts),
  {ok, Pid} = gen_server:start_link(via(Socket), ?MODULE, [Socket, Opts], []),
  controlling_process(Socket, Pid),
  {ok, Socket}.


-spec connect(Socket, IP, Port) -> Result when
    Socket :: gen_quic:socket(),
    IP :: inet:address(),
    Port :: non_neg_integer(),
    Result :: ok.

connect(Socket, IP, Port) ->  
  gen_server:cast(via(Socket), {connect, IP, Port}).


-spec reconnect(Socket, IP, Port) -> Result when
    Socket :: gen_quic:socket(),
    IP :: inet:address(),
    Port :: non_neg_integer(),
    Result :: ok.

reconnect(Socket, IP, Port) ->
  gen_server:cast(via(Socket), {connect, IP, Port}).

-spec send(Socket, Packet) -> Result when
    Socket :: gen_quic:socket(),
    Packet :: binary(),
    Result :: ok.

send(Socket, Packet) ->
  gen_server:cast(via(Socket), {send, Packet}).


%% Signals the gen_server should stop once all packets have been 
%% sent and acked.
-spec close(Socket) -> Result when
    Socket :: gen_quic:socket(),
    Result :: ok.

close(Socket) ->
  gen_server:cast(via(Socket), close).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

-spec init(Args :: term()) -> {ok, State :: term()} |
                              {ok, State :: term(), Timeout :: timeout()} |
                              {ok, State :: term(), hibernate} |
                              {stop, Reason :: term()} |
                              ignore.

init([Socket, Opts]) ->
  process_flag(trap_exit, true),
  State =  #state{
              socket=Socket, 
              options=Opts,
              sent=queue:new(),
              unsent=queue:new()
             },
  {ok, State}.


-spec handle_call(Request :: term(), From :: {pid(), term()}, State :: term()) ->
                     {reply, Reply :: term(), NewState :: term()} |
                     {reply, Reply :: term(), NewState :: term(), Timeout :: timeout()} |
                     {reply, Reply :: term(), NewState :: term(), hibernate} |
                     {noreply, NewState :: term()} |
                     {noreply, NewState :: term(), Timeout :: timeout()} |
                     {noreply, NewState :: term(), hibernate} |
                     {stop, Reason :: term(), Reply :: term(), NewState :: term()} |
                     {stop, Reason :: term(), NewState :: term()}.

handle_call({connect, IP, Port}, _From, #state{socket=Socket}=State) ->
  prim_inet:connect(Socket, IP, Port),
  {reply, ok, State};

handle_call(_Request, _From, State) ->
  Reply = ok,
  {reply, Reply, State}.



-spec handle_cast(Request :: term(), State :: term()) ->
                     {noreply, NewState :: term()} |
                     {noreply, NewState :: term(), Timeout :: timeout()} |
                     {noreply, NewState :: term(), hibernate} |
                     {stop, Reason :: term(), NewState :: term()}.

handle_cast({send, Packet}, #state{unsent=Unsent}=State) ->
  {noreply, State#state{unsent=queue:in(Unsent, Packet)}};

handle_cast(close, #state{socket=Socket, 
                          unsent=Unsent, 
                          sent=Sent}=State) ->
  case {queue:is_empty(Unsent),
        queue:is_empty(Sent)} of
    {true, true} ->
      inet:udp_close(Socket),
      {stop, normal};

    _Not_Done ->
      %% Check again in 500 milliseconds
      start_timer(500, self(), close),
      {noreply, State}
  end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%% @end
%%--------------------------------------------------------------------
-spec handle_info(Info :: timeout() | term(), State :: term()) ->
                     {noreply, NewState :: term()} |
                     {noreply, NewState :: term(), Timeout :: timeout()} |
                     {noreply, NewState :: term(), hibernate} |
                     {stop, Reason :: normal | term(), NewState :: term()}.

handle_info(close, #state{socket=Socket, 
                          unsent=Unsent, 
                          sent=Sent}=State) ->
  case {queue:is_empty(Unsent),
        queue:is_empty(Sent)} of
    {true, true} ->
      inet:udp_close(Socket),
      {stop, normal};

    _Not_Done ->
      %% Check again in 500 milliseconds
      start_timer(500, self(), close),
      {noreply, State}
  end;

handle_info(Info, State) ->
  {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%% @end
%%--------------------------------------------------------------------
-spec terminate(Reason :: normal | shutdown | {shutdown, term()} | term(),
                State :: term()) -> any().
terminate(_Reason, _State) ->
  ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%% @end
%%--------------------------------------------------------------------
-spec code_change(OldVsn :: term() | {down, term()},
                  State :: term(),
                  Extra :: term()) -> {ok, NewState :: term()} |
                                      {error, Reason :: term()}.
code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called for changing the form and appearance
%% of gen_server status when it is returned from sys:get_status/1,2
%% or when it appears in termination error logs.
%% @end
%%--------------------------------------------------------------------
-spec format_status(Opt :: normal | terminate,
                    Status :: list()) -> Status :: term().
format_status(_Opt, Status) ->
  Status.

%%%===================================================================
%%% Internal functions
%%%===================================================================


via(Name) ->
  {via, quic_registry, Name}.
