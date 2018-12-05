%%%-------------------------------------------------------------------
%%% @author alex
%%% @copyright (C) 2018, alex
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(inet_quic_util).

%% API
-export([quic_module/0, quic_module/1, quic_module/2]).
-export([getservbyname/2]).
-export([is_opt/2]).
-export([get_opt/2]).
-export([parse_opts/1]).

-include("quic_headers.hrl").

%%%===================================================================
%%% API
%%%===================================================================

-spec parse_opts(Option_List) -> Result when
    Option_List :: [Option],
    Option :: gen_quic:option() |
              gen_quic:stream_option() |
              gen_udp:option(),
    Result :: {ok, Quic_Options, Udp_Options} |
              {error, [Reason]},
    Quic_Options :: #{gen_quic:option_name() => any()},
    Udp_Options :: [gen_udp:option()],
    Reason :: {invalid_option, gen_quic:option()} |
              {unknown_option, any()}.

%% Separates the quic option parameters from the udp socket parameters.
%% Verifies that the quic options are valid and sets default values.
%% Returns a list of Errors or the parsed options. Does not validate the udp options.
parse_opts(Opts) ->
  parse_opts(Opts, #{}, [], []).

parse_opts([], _Opts, _Udp_Opts, Errors) when length(Errors) > 0 ->
  {error, Errors};

parse_opts([], Opts, Udp_Opts, _Errors) ->
  {ok, Opts, Udp_Opts};

parse_opts([{max_data, Int} | Rest], Opts, Udp_Opts, Errors) when Int > 0 ->
  parse_opts(Rest, Opts#{max_data => Int}, Udp_Opts, Errors);

parse_opts([{max_stream_count_bidi, Int} | Rest], Opts, Udp_Opts, Errors) when Int > 0 ->
  parse_opts(Rest, Opts#{max_stream_count_bidi => Int}, Udp_Opts, Errors);

parse_opts([{max_peer_stream_count_bidi, Int} | Rest], Opts, Udp_Opts, Errors) when Int > 0 ->
  parse_opts(Rest, Opts#{max_peer_stream_count_bidi => Int}, Udp_Opts, Errors);

parse_opts([{max_stream_count_uni, Int} | Rest], Opts, Udp_Opts, Errors) when Int > 0 ->
  parse_opts(Rest, Opts#{max_stream_count_uni => Int}, Udp_Opts, Errors);

parse_opts([{max_peer_stream_count_uni, Int} | Rest], Opts, Udp_Opts, Errors) when Int > 0 ->
  parse_opts(Rest, Opts#{max_peer_stream_count_uni => Int}, Udp_Opts, Errors);

parse_opts([{max_stream_data_bidi, Size} | Rest], Opts, Udp_Opts, Errors) ->
  parse_opts(Rest, Opts#{max_stream_data_bidi => Size}, Udp_Opts, Errors);

parse_opts([{max_stream_data_uni, Size} | Rest], Opts, Udp_Opts, Errors) ->
  parse_opts(Rest, Opts#{max_stream_data_uni => Size}, Udp_Opts, Errors);

parse_opts([{max_peer_stream_data_bidi, Size} | Rest], Opts, Udp_Opts, Errors) ->
  parse_opts(Rest, Opts#{max_peer_stream_data_bidi => Size}, Udp_Opts, Errors);

parse_opts([{max_peer_stream_data_uni, Size} | Rest], Opts, Udp_Opts, Errors) ->
  parse_opts(Rest, Opts#{max_peer_stream_data_uni => Size}, Udp_Opts, Errors);

parse_opts([{idle_timeout, Timeout} | Rest], Opts, Udp_Opts, Errors) when Timeout > 5000 ->
  %% I am arbitrarily setting a lower bound on the idle timeout to 5000 ms or 5 secs.
  parse_opts(Rest, Opts#{idle_timeout => Timeout}, Udp_Opts, Errors);

parse_opts([{preferred_address, {Address, Port, Conn_Id, Reset_Token}} | Rest], 
           Opts, Udp_Opts, Errors) ->
  %% This will need tweaking to check that each of the fields are valid.
  Pref_Address = #{address => Address,
                   port => Port,
                   conn_id => Conn_Id,
                   reset_token => Reset_Token
                  },
  parse_opts(Rest, Opts#{preferred_address => Pref_Address}, Udp_Opts, Errors);

parse_opts([{max_packet_size, Size} | Rest], Opts, Udp_Opts, Errors) when 
    Size < 65508, Size > 1200 ->
  %% 65507 bytes is the maximum size of a udp packet. 1200 is the minimum size of a quic packet.
  parse_opts(Rest, Opts#{max_packet_size => Size}, Udp_Opts, Errors);

parse_opts([{token_params, {application, Module, Function, Args} = Params} | Rest], 
           Opts, Udp_Opts, Errors) when is_atom(Module), 
                                        is_atom(Function), 
                                        is_list(Args) ->
  %% Call the application specific {Module, Function, Args} to generate a token.
  parse_opts(Rest, Opts#{token_params => Params}, Udp_Opts, Errors);

parse_opts([{token_params, {size, _Bytes} = Params} | Rest], Opts, Udp_Opts, Errors) ->
  %% Create a random token of Bytes size.
  parse_opts(Rest, Opts#{token_params => Params}, Udp_Opts, Errors);

parse_opts([{ack_delay_exp, Int} | Rest], Opts, Udp_Opts, Errors) 
  when Int =< 20, Int >= 0 ->
  %% "Values above 20 are invalid." Section 18.1
  %% Negative numbers wouldn't make sense.
  parse_opts(Rest, Opts#{ack_delay_exp => Int}, Udp_Opts, Errors);

parse_opts([{disable_migration, Bool} | Rest], Opts, Udp_Opts, Errors) when is_boolean(Bool) ->
  parse_opts(Rest, Opts#{disable_migration => Bool}, Udp_Opts, Errors);

parse_opts([{max_ack_delay, MS} | Rest], Opts, Udp_Opts, Errors) when MS >= 0 ->
  %% A value delay less than zero does not make sense.
  parse_opts(Rest, Opts#{max_ack_delay => MS}, Udp_Opts, Errors);

parse_opts([{init_conn_id, Conn_Id} | Rest], Opts, Udp_Opts, Errors) 
  when is_binary(Conn_Id), byte_size(Conn_Id) < 15, 
       (byte_size(Conn_Id) == 0 orelse byte_size(Conn_Id) >= 3) ->
  parse_opts(Rest, Opts#{init_conn_id => Conn_Id}, Udp_Opts, Errors);

parse_opts([{active, Bool} | Rest], Opts, Udp_Opts, Errors) when is_boolean(Bool)->
  parse_opts(Rest, Opts#{active => Bool}, Udp_Opts, Errors);

parse_opts([{active, once} | Rest], Opts, Udp_Opts, Errors) ->
  parse_opts(Rest, Opts#{active => once}, Udp_Opts, Errors);

parse_opts([{active, N} | Rest], Opts, Udp_Opts, Errors) when N >= 0 ->
  parse_opts(Rest, Opts#{active => N}, Udp_Opts, Errors);

parse_opts([{mode, list} | Rest], Opts, Udp_Opts, Errors) ->
  parse_opts(Rest, Opts#{mode => list}, Udp_Opts, Errors);

parse_opts([{mode, binary} | Rest], Opts, Udp_Opts, Errors) ->
  parse_opts(Rest, Opts#{mode => binary}, Udp_Opts, Errors);

parse_opts([list | Rest], Opts, Udp_Opts, Errors) ->
  parse_opts(Rest, Opts#{mode => list}, Udp_Opts, Errors);

parse_opts([binary | Rest], Opts, Udp_Opts, Errors) ->
  parse_opts(Rest, Opts#{mode => binary}, Udp_Opts, Errors);

parse_opts([{version, Version} = Option | Rest], Opts, Udp_Opts, Errors) when is_binary(Version) ->
  case quic_vxx:supported(Version) of
    {error, unsupported} ->
      parse_opts(Rest, Opts, Udp_Opts, [{invalid_option, Option} | Errors]);

    {ok, {Module, Version}} ->
      parse_opts(Rest, Opts#{version => Version,
                             version_module => Module},
                 Udp_Opts, Errors)
  end;

parse_opts([{version, Version} | Rest], Opts, Udp_Opts, Errors) when is_list(Version) ->
  Ver_Bin = list_to_binary(Version),
  parse_opts([{version, Ver_Bin} | Rest], Opts, Udp_Opts, Errors);

parse_opts([{supported_versions, Version_List} = Option | Rest], Opts, Udp_Opts, Errors) ->
  Bin_Check = fun (Vx) when is_binary(Vx) -> Vx;
                  (Vx) when is_list(Vx)   -> list_to_binary(Vx);
                  (_Vx) -> error end,
  Vx_Check = fun (Vx, {ok, Valid}) -> 
                 case quic_vxx:supported(Vx) of
                   {error, unsupported} ->
                     error;
                   {ok, {Module, Vx}} ->
                     {ok, [{Module, Vx} | Valid]}
                 end;
                 (_, error) -> error;
                 (error, _) -> error
             end,

  Vx_Bins = lists:map(Bin_Check, Version_List),
  case lists:foldl(Vx_Check, {ok, []}, Vx_Bins) of
    {ok, Valid} -> 
      parse_opts(Rest, Opts#{supported_versions => lists:reverse(Valid)}, Udp_Opts, Errors);
    error ->
      parse_opts(Rest, Opts, Udp_Opts, [{invalid_option, Option} | Errors])
  end;

parse_opts([{Other, _Value} = Option | Rest], Opts, Udp_Opts, Errors) ->
  case {lists:member(Other, udp_options()),
        lists:member(Other, quic_options())
       } of
    {true, _} -> parse_opts(Rest, Opts, [Option | Udp_Opts], Errors);

    {false, false} -> 
      Error = {unknown_option, Option},
      parse_opts(Rest, Opts, Udp_Opts, [Error | Errors]);

    {false, true} ->
      Error = {invalid_option, Option},
      parse_opts(Rest, Opts, Udp_Opts, [Error | Errors])
  end.


%% This list is copied from the inet.erl module in the standard library.  
udp_options() ->
  [tos, tclass, priority, reuseaddr, sndbuf, recbuf, header, active, buffer, mode,
   recvtos, recvtclass, ttl, recvttl, deliver, ipv6_v6only,
   broadcast, dontroute, multicast_if, multicast_ttl, multicast_loop,
   add_membership, drop_membership, read_packets,raw,
   high_msgq_watermark, low_msgq_watermark, bind_to_device].

quic_options() ->
  [supported_versions, version, max_data, max_stream_count_bidi, max_stream_count_uni,
   idle_timeout, preferred_address, max_packet_size, token_params, ack_delay_exp,
   max_ack_delay, disable_migration, active, mode, list, binary, init_conn_id,
   max_stream_data_bidi, max_stream_data_uni, max_peer_stream_count_bidi,
   max_peer_stream_count_uni, max_stream_count_uni, max_stream_count_bidi,
   max_peer_stream_data_bidi, max_peer_stream_data_uni].

%% Returns true if the given option is defined, otherwise returns false.
%% Just a wrapper for lists:keymember.
is_opt(Opts, Field) ->
  lists:keymember(Field, 1, Opts).


get_opt(Opts, Type) ->
  proplists:lookup(Type, Opts).

quic_module() ->
  inet_quic.

quic_module(Opts) ->
  %% Calling inet's mod function should work, but it isn't exported.
  mod(Opts, quic_module, undefined, #{inet => inet_quic,
                                      inet6 => inet6_quic,
                                      local => inet_quic}).

quic_module(Opts, Address) ->
  mod(Opts, quic_module, Address, #{inet => inet_quic,
                                    inet6 => inet6_quic,
                                    local => inet_quic}).


%% Copied from inet.erl module. It isn't exported otherwise I would just call it.
mod(Opts, Tag, Address, Map) ->
  mod(Opts, Tag, Address, Map, undefined, []).

mod([{Tag, M}|Opts], Tag, Address, Map, Mod, Acc) ->
  mod(Opts, Tag, Address, Map, Mod, Acc, M);

mod([{T, _} = Opt|Opts], Tag, _Address, Map, Mod, Acc)
  when T =:= ip; T =:= ifaddr->
  mod(Opts, Tag, Opt, Map, Mod, [Opt|Acc]);

mod([Family|Opts], Tag, Address, Map, Mod, Acc) when is_atom(Family) ->
  case Map of
    #{Family := M} ->
      mod(Opts, Tag, Address, Map, Mod, Acc, M);
    #{} ->
      mod(Opts, Tag, Address, Map, Mod, [Family|Acc])
  end;

mod([Opt|Opts], Tag, Address, Map, Mod, Acc) ->
  mod(Opts, Tag, Address, Map, Mod, [Opt|Acc]);

mod([], Tag, Address, Map, undefined, Acc) ->
  {case Address of
     {_, {local, _}} ->
       %% This is only needed for SCTP connections which do not have a local option.
       %% Using map:get/3 probably works better in my opinion anyways.
       %% case Map of
       %%   #{local := Mod} ->
       %%     Mod;
       %%   _ ->
       %%     inet_db:Tag()
       %% end;       
       maps:get(local, Map, inet_quic_util:Tag());

     {_, IP} when tuple_size(IP) =:= 8 ->
       #{inet := IPv4Mod} = Map,
       %% Get the mod, but IPv6 address overrides default IPv4
       case inet_quic_util:Tag() of
         IPv4Mod ->
           #{inet6 := IPv6Mod} = Map,
           IPv6Mod;
         Mod ->
           Mod
       end;
     _ ->
       inet_quic_util:Tag()
   end, lists:reverse(Acc)};

mod([], _Tag, _Address, _Map, Mod, Acc) ->
  {Mod, lists:reverse(Acc)}.


mod(Opts, Tag, Address, Map, undefined, Acc, M) ->
  mod(Opts, Tag, Address, Map, M, Acc);

mod(Opts, Tag, Address, Map, Mod, Acc, _M) ->
  mod(Opts, Tag, Address, Map, Mod, Acc).


%% Some of the other inet functions might make an appearance here eventually.
%% Just switching out the quic protocol name for udp before passing to inet.
getservbyname(Name, _Protocol) ->
  case inet:getservbyname(Name, udp) of
    inet_udp ->
      inet_quic;
    inet6_udp ->
      inet6_quic
  end.

%%%===================================================================
%%% Internal functions
%%%===================================================================
