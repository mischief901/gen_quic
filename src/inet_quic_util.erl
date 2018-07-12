%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%%
%%% @end
%%% Created : 15 May 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(inet_quic_util).

%% API
-export([quic_module/1]).
-export([getservbyname/2]).
-export([is_opt/2]).
-export([get_opt/2]).

%%%===================================================================
%%% API
%%%===================================================================


%% Returns true if the given option is defined, otherwise returns false.
%% Just a wrapper for lists:keymember.
is_opt(Opts, Field) ->
  lists:keymember(Field, 1, Opts).


get_opt(Opts, Type) ->
  proplists:lookup(Type, Opts).


quic_module(Opts) ->
    %% Calling inet's mod function should work, but it isn't exported.
    mod(
      Opts, quic_module, undefined,
      #{inet => inet_quic, inet6 => inet6_quic}).

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
	     case Map of
		 #{local := Mod} ->
		     Mod;
		 #{} ->
		     inet_db:Tag()
	     end;
	 {_, IP} when tuple_size(IP) =:= 8 ->
	     #{inet := IPv4Mod} = Map,
	     %% Get the mod, but IPv6 address overrides default IPv4
	     case inet_db:Tag() of
		 IPv4Mod ->
		     #{inet6 := IPv6Mod} = Map,
		     IPv6Mod;
		 Mod ->
		     Mod
	     end;
	 _ ->
	     inet_db:Tag()
     end, lists:reverse(Acc)};

mod([], _Tag, _Address, _Map, Mod, Acc) ->
    {Mod, lists:reverse(Acc)}.

%%

mod(Opts, Tag, Address, Map, undefined, Acc, M) ->
    mod(Opts, Tag, Address, Map, M, Acc);

mod(Opts, Tag, Address, Map, Mod, Acc, _M) ->
    mod(Opts, Tag, Address, Map, Mod, Acc).


%%

getservbyname(Name, _Protocol) ->
    inet:getservbyname(Name, udp).


%%%===================================================================
%%% Internal functions
%%%===================================================================
