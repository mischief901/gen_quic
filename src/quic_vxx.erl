%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%% This is a generic quic version for testing and setting the API.
%%% @end
%%% Created : 18 May 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_vxx).

%% API
-export([version/0, get_type/1]).

%%%===================================================================
%%% API
%%%===================================================================

version() ->
    {quic_vxx, "quic_vxx"}.


%% Parses type information dependent on the version number.
get_type(Data) ->
    ok.





%%%===================================================================
%%% Internal functions
%%%===================================================================
