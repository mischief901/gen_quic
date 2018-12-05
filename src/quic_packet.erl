%%%-------------------------------------------------------------------
%%% @author alex
%%% @copyright (C) 2018, alex
%%% @doc
%%%  This module splits the packet into a list of tuples with header
%%%  information and encoded frames. It also checks to see if the version
%%%  is supported and sets the version specific module for parsing and
%%%  forming frames.
%%%
%%%  The parse_header/2 function returns a list due to the possibility of
%%%  coalesced packets.
%%% @end
%%%-------------------------------------------------------------------
-module(quic_packet).

%% API
-export([parse_header/2]).
-export([parse_frames/2]).
-export([form_packet/2, form_packet/3, form_packet/4]).
-export([form_frame/2]).

-include("quic_headers.hrl").

%%%===================================================================
%%% API
%%%===================================================================

%% Checks the header of the packet for the correct information.
%% Separates out the Token for initial packets and sets the conn_ids for the initial
%% packet received by the server.
%% If it is an invariant packet (retry or vx_neg) then it parses everything.
%% Otherwise returns the length of the payload and header.
-spec parse_header(Raw_Packet, Data) -> Result when
    Raw_Packet :: binary(),
    Data :: quic_data(),
    Result :: {ok, Data, Header_Info} |
              {ok, Data} |
              {error, Reason},
    Reason :: gen_quic:error(),
    Header_Info :: {initial, Reset_Token, Payload_Length, Header_Length} |
                   {Other_Type, Payload_Length, Header_Length} |
                   Invariant_Type,
    Other_Type :: early_data |
                  handshake |
                  short,
    Invariant_Type :: {vx_neg, Versions} |
                      {retry, Retry_Reason},
    Retry_Reason :: {new_dcid, conn_id()} | any(), 
    %% TODO: Update type when retry packets are figured out.
    Versions :: [Version],
    Version :: version(),
    Reset_Token :: binary(),
    Payload_Length :: non_neg_integer(),
    Header_Length :: non_neg_integer().

parse_header(<<1:1, _Type:7, 0:32, DCIL:4, SCIL:4,
               Rest/binary>>,
             #{conn := #{src_conn_ID := Dest_Conn,
                         dest_conn_ID := Src_Conn}
               } = Data) ->
  %% Version Negotiation Packet
  %% Make sure the packet has the correct source and destination connection id's.
  Dest_Len = quic_utils:from_conn_length(DCIL),
  Src_Len = quic_utils:from_conn_length(SCIL),
  
  <<Dest:Dest_Len/binary, Src:Src_Len/binary, Vx_Frames/binary>> = Rest,

  case {Dest, Src} of
    {Dest_Conn, Src_Conn} ->
      %% Both match.
      %% No header or packet number info is relevant.
      Versions = quic_utils:binary_foldl(fun (Bin, Acc) -> [Bin | Acc] end,
                                         [], Vx_Frames, 4),
      {ok, Data, {vx_neg, lists:reverse(Versions)}};
    
    _Other ->
      {error, protocol_violation}
  end;

parse_header(<<1:1, 16#7e:7, Version:4/binary, DCIL:4, SCIL:4, Rest/binary>>,
             #{version := #{initial_version := Version},
                conn := #{dest_conn_ID := Dest_Conn,
                          src_conn_ID := Src_Conn}
               } = Data0) ->
  %% Retry packet
  %% First get the DCIL and SCIL lengths
  Dest_Len = quic_utils:from_conn_length(DCIL),
  Src_Len = quic_utils:from_conn_length(SCIL),
  Old_Dest_Len = byte_size(Dest_Conn),

  case Rest of
    <<New_Dest_Conn:Dest_Len/binary, Src_Conn:Src_Len/binary, 
      Old_Dest_Len:8, Dest_Conn:Old_Dest_Len/binary, Retry_Token/binary>> ->
      %% Since the old dest_conn matches, return the new dcid and retry_token.
      {ok, Data0, {retry, {new_dcid, New_Dest_Conn, Retry_Token}}};
   %% More cases to be added.
    _Other ->
      %% Otherwise ignore the packet.
      {ok, Data0}
  end;

parse_header(<<1:1, Type:7, Version:4/binary, Rest/binary>>, Data) ->
  %% Long header type.
  parse_long_header(Rest, Data, Type, Version, 5);

parse_header(<<0:1, Type:7/bits, Rest/binary>>, Data) ->
  %% Short header type.
  parse_short_header(Rest, Data, Type, 1).

parse_long_header(<<DCIL:4, SCIL:4, Rest/binary>>,
                  #{version := #{negotiated_version := Version}
                    } = Data,
                  Type_Num, Version, Header_Length) ->
  %% The versions match so continue.
  Type = case Type_Num of
           16#7d ->
             handshake;
           16#7c ->
             early_data
         end,
  
  Dest_Len = quic_utils:from_conn_length(DCIL),
  Src_Len = quic_utils:from_conn_length(SCIL),
  
  parse_conns(Rest, Data, Type, {Dest_Len, Src_Len}, Header_Length + 1);

parse_long_header(<<DCIL:4, SCIL:4, Rest/binary>>,
                  Data0,
                  16#7f, Version, Header_Length) ->
  %% Initial packet. Need to check if the version is supported
  Dest_Len = quic_utils:from_conn_length(DCIL),
  Src_Len = quic_utils:from_conn_length(SCIL),

  io:format("Checking Version: ~p~n", [Version]),

  case quic_vxx:supported(Version) of
    {ok, {Module, Version}} ->
      Data = Data0#{version => #{initial_version => Version,
                                 negotiated_version => Version
                                },
                    vx_module => Module
                   },
      io:format("Header ln 143: ~p~n", [Header_Length]),
      parse_conns(Rest, Data, initial, {Dest_Len, Src_Len}, Header_Length + 1);
    
    {error, unsupported} ->
      parse_conns(Rest, Data0, unsupported, {Dest_Len, Src_Len}, unsupported)

  end;

parse_long_header(_, _, _, _, _) ->
  io:format(standard_error, "\tInvalid Version received in header.~n", []),
  {error, invalid_header}.


parse_short_header(<<Header/binary>>, 
                   #{conn := #{src_conn_ID := Dest_Conn}} = Data,
                   Type, Header_Length) ->
  %% Type flags to be implemented.
  Dest_Len = quic_utils:to_conn_length(Dest_Conn),
  
  case Header of
    <<Dest_Conn:Dest_Len/binary, Packet/binary>> ->
      {ok, Data, {short, Header_Length, byte_size(Packet)}};
    
    _Wrong_Conn ->
      io:format(standard_error, "\tWrong Connection id received in short packet~n", []),
      {error, invalid_header}
  end.


parse_conns(<<Rest/binary>>, 
            #{conn := Conn} = Data0, 
            unsupported, {Dest_Len, Src_Len}, unsupported) ->
  <<Dest_Conn:Dest_Len/binary, Src_Conn:Src_Len/binary, _Unused>> = Rest,
  
  Data = Data0#{conn := Conn#{dest_conn_ID => Dest_Conn,
                              src_conn_ID => Src_Conn}},
  {unsupported, Data};

parse_conns(<<Header/binary>>,
            #{conn := #{dest_conn_ID := Src_Conn,
                        src_conn_ID := Dest_Conn}} = Data,
            initial, {Dest_Len, Src_Len}, Header_Length) ->
  case Header of
    <<Dest_Conn:Dest_Len/binary, Src_Conn:Src_Len/binary, Token_Length_Flag:2, Rest/bits>> ->
      Token_Length_Len = quic_utils:from_var_length(Token_Length_Flag),
      parse_token(Rest, Data, initial, Token_Length_Len, Header_Length + Dest_Len + Src_Len);
    
    _Wrong_Conn ->
      io:format(standard_error, "\tWrong Conn received with packet.~n", []),
      {error, invalid_initial}
  end;

parse_conns(<<Header/bits>>,
           #{conn := #{dest_conn_ID := Dest_Conn,
                       src_conn_ID := Src_Conn}} = Data,
            Type, {Dest_Len, Src_Len}, Header_Length) ->
  case Header of
    <<Dest_Conn:Dest_Len/binary, Src_Conn:Src_Len/binary, Length_Flag:2, Rest/bits>> ->
      %% The connection ids match.
      Length_Length = quic_utils:from_var_length(Length_Flag),
      parse_length(Rest, Data, Type, Length_Length, Header_Length + Dest_Len + Src_Len);
    _Wrong_Conns ->
      io:format(standard_error, "\tWrong Conn received with packet.~n", []),
      {error, invalid_initial}
  end;

parse_conns(<<Header/binary>>,
            #{conn := Conn0} = Data0,
            initial, {Dest_Len, Src_Len}, Header_Length) ->
  <<Dest_Conn:Dest_Len/binary, Src_Conn:Src_Len/binary, Token_Length_Flag:2, Rest/bits>> = Header,
  Data = Data0#{conn := Conn0#{dest_conn_ID => Src_Conn,
                               src_conn_ID => Dest_Conn}},  
  Token_Length = quic_utils:from_var_length(Token_Length_Flag),
  parse_token(Rest, Data, initial, Token_Length, Header_Length + Dest_Len + Src_Len).

parse_token(<<Header/bits>>, Data, initial, Token_Length_Len, Header_Length) ->
  <<Token_Len:Token_Length_Len, Rest/bits>> = Header,
  Length_Bytes = (Token_Length_Len + 2) div 8,
  parse_token_(Rest, Data, initial, Token_Len, Header_Length + Length_Bytes).

parse_token_(<<Header/bits>>, Data, initial, Token_Len, Header_Length) ->
  
  <<Token:Token_Len/binary, Length_Flag:2, Rest/bits>> = Header,
  Length_Length = quic_utils:from_var_length(Length_Flag),
  parse_length(Rest, Data, {initial, Token}, Length_Length, Header_Length + Token_Len).

parse_length(<<Header/bits>>, Data, Type, Length_Length, Header_Length) ->
  <<Length:Length_Length, _Rest/binary>> = Header,
  Length_Bytes = (Length_Length + 2) div 8,
  case Type of
    {initial, Token} ->
      {ok, Data, {initial, Token, Length, Header_Length + Length_Bytes}};

    _Other ->
      {ok, Data, {Type, Length, Header_Length + Length_Bytes}}
  end.


-spec parse_frames(Payload, Data) -> Result when
    Payload :: binary(),
    Data :: quic_data(),
    Result :: {ok, Data, Frames, Acks, TLS_Frame} |
              {error, Reason},
    Frames :: [quic_frame()],
    Acks :: [quic_frame()],
    TLS_Frame :: binary(),
    Reason :: gen_quic:error().

parse_frames(<<Payload/binary>>, 
             #{vx_module := Module}) ->
  Module:parse_frames(Payload).


-spec form_packet(vx_neg, Data) -> Result when
    Data :: quic_data(),
    Result :: {ok, Data, Packet} | {error, Reason},
    Packet :: binary(),
    Reason :: gen_quic:error().

%% form_packet/2 is used to create retry and vx_neg packets.
%% If the version chosen by the client is not supported,
%% this creates a vx_neg packet from the supported_versions list in version.
%% For retry packets the initial version is used.
form_packet(vx_neg, 
            #{conn := #{dest_conn_ID := Dest_Conn,
                       src_conn_ID := Src_Conn
                       },
              version := #{supported_versions := Versions}
             } = Data) ->
  <<_:1, Rand:7>> = crypto:strong_rand_bytes(1),
  Version = <<0:4/unit:8>>,
  Dest_Len = quic_utils:to_conn_length(Dest_Conn),
  Src_Len = quic_utils:to_conn_length(Src_Conn),
  Supported = lists:foldl(fun(Vx, Acc) when byte_size(Vx) == 4 -> <<Acc/binary, Vx/binary>> end,
                          <<>>, Versions),
  Packet = <<1:1, Rand:7, Version/binary, Dest_Len:4, Src_Len:4,
             Dest_Conn/binary, Src_Conn/binary, Supported/binary>>,
  {ok, Data, Packet}.


-spec form_packet(Type, Data, Frames) -> Result when
    Type :: retry |
            initial |
            early_data |
            handshake |
            short,
    Data :: quic_data(),
    Frames :: [quic_frame()] | New_Conn_Id,
    New_Conn_Id :: binary(),
    Result :: {ok, Data, Header, Payload, Pkt_Num} | {error, Reason},
    Header :: binary(),
    Payload :: binary(),
    Pkt_Num :: {non_neg_integer(), binary()},
    Reason :: gen_quic:error().

%% The version is known and agreed upon. We still need to lookup the correct module
%% Somehow this needs to make sure that the initial packet from a client or server
%% has only the information normally sent then.
%% Same for the handshake packets.
form_packet(Type,
            #{version := #{negotiated_version := Version},
              vx_module := undefined
             } = Data0,
            Frames) ->
  case quic_vxx:supported(Version) of
    {ok, {Module, Version}} ->
      Data = Data0#{vx_module := Module},
      Module:form_packet(Type, Data, Frames);
    
    {error, unsupported} ->
      {error, unsupported};

    Other ->
      Other
  end;

%% The version_module is already known at this point so we don't need to look it up
form_packet(Type, #{vx_module := Module} = Data, Frames) ->
  Module:form_packet(Type, Data, Frames).


-spec form_packet(retry, Data, New_Dest_Conn, Token) -> {ok, Data, Packet} when
    Data :: quic_data(),
    New_Dest_Conn :: binary(),
    Token :: binary(),
    Packet :: binary().

form_packet(retry, #{type := server,
                     conn := #{dest_conn_ID := Old_Dest_Conn,
                               src_conn_ID := Src_Conn
                              } = Conn0,
                     version := #{initial_version := Vx_Init,
                                  negotiated_version := Vx_Neg
                                 }
                    } = Data0, New_Dest_Conn, Token) ->
  Version = case Vx_Neg of
              undefined -> Vx_Init;
              _ -> Vx_Neg
            end,
  <<Rand:4, _/bits>> = crypto:strong_rand_bytes(1),
  Old_Dest_Len = quic_utils:to_conn_length(Old_Dest_Conn),
  Dest_Len = quic_utils:to_conn_length(New_Dest_Conn),
  Src_Len = quic_utils:to_conn_length(Src_Conn),
  Packet = <<1:1, 16#7e:7, Version/binary, Dest_Len:4, Src_Len:4, New_Dest_Conn/binary,
             Src_Conn/binary, Rand:4, Old_Dest_Len:4, Old_Dest_Conn/binary,
             Token/binary>>,
  Data = Data0#{conn := Conn0#{dest_conn_ID := New_Dest_Conn},
                retry_token := Token},
  {ok, Data, Packet}.


-spec form_frame(Version, Frame_Info) -> Result when
    Version :: binary() | atom(),
    Frame_Info :: quic_frame(),
    Result :: {ok, quic_frame()} |
              {error, Reason},
    Reason :: gen_quic:frame_error().

%% form_frame(_, #{}) ->
%%   %% Nothing to form so return an empty frame.
%%   {ok, #{type => empty, binary => <<>>}};

form_frame(Version, Frame_Info) when is_binary(Version) ->
  {ok, {Module, Version}} = quic_vxx:supported(Version),
  Module:form_frame(Frame_Info);

form_frame(Module, Frame_Info) when is_atom(Module) ->
  Module:form_frame(Frame_Info).


%%%%%%%%%%
%%  Internal Functions
%%%%%%%%%%


