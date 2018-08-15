%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
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
%%% Created : 16 May 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_packet).

%% API
-export([parse_header/2]).
%%-export([parse_frames/2]).
-export([form_packet/2, form_packet/3]).
-export([form_header/3]).

-include("quic_headers.hrl").

%%%===================================================================
%%% API
%%%===================================================================

%% Splits the packet into a list of tuples with header information and
%% encoded frames.
-spec parse_header(Raw_Packet, Data) -> Result when
    Raw_Packet :: binary(),
    Data :: #quic_data{},
    Result :: [Packet] |
              {error, Reason} |
              not_quic,
    Reason :: gen_quic:errors(),
    Packet :: {initial, Data, Header, Pkt_Num, Reset_Token, Encoded_Frames} |
              {Other_Type, Data, Header, Pkt_Num, Encoded_Frames},
    Other_Type :: early_data |
                  handshake |
                  short |
                  vx_neg |
                  retry,
    Pkt_Num :: binary(),
    Reset_Token :: binary(),
    Encoded_Frames :: binary(),
    Header :: binary().

parse_header(<<1:1, _Type:7, 0:32, DCIL:4, SCIL:4,
               Rest/binary>>,
             #quic_data{
                conn = #quic_conn{
                          src_conn_ID = Dest_Conn,
                          dest_conn_ID = Src_Conn
                         }
               } = Data) ->
  %% Version Negotiation Packet
  %% Make sure the packet has the correct source and destination connection id's.
  Dest_Len = conn_length(DCIL),
  Src_Len = conn_length(SCIL),
  
  <<Dest:Dest_Len/binary, Src:Src_Len/binary, Vx_Frames/binary>> = Rest,

  case {Dest, Src} of
    {Dest_Conn, Src_Conn} ->
      %% Both match.
      %% No header or packet number info is relevant.
      [{vx_neg, Data, <<>>, <<>>, Vx_Frames}];
    
    _Other ->
      {error, protocol_violation}
  end;

parse_header(<<1:1, 16#7e:7, Version:4/binary, DCIL:4, SCIL:4, Rest/binary>>,
             #quic_data{
                version = #quic_version{
                             initial_version = Version
                            },
                conn = #quic_conn{
                          dest_conn_ID = Dest_Conn,
                          src_conn_ID = Src_Conn
                         } = Conn0
               } = Data0) ->
  %% Retry packet
  %% First get the DCIL and SCIL lengths
  Dest_Len = conn_length(DCIL),
  Src_Len = conn_length(SCIL),
  Old_Dest_Len = byte_size(Dest_Conn),

  case Rest of
    <<New_Dest_Conn:Dest_Len/binary, Src_Conn:Src_Len/binary, 
      Old_Dest_Len:8, Dest_Conn:Old_Dest_Len/binary, Retry_Token/binary>> ->
      
      Data = Data0#quic_data{
               conn = Conn0#quic_conn{
                        dest_conn_ID = New_Dest_Conn
                       },
               retry_token = Retry_Token
              },
      %% Header, Packet_Number, and Frames are not needed.
      [{retry, Data, <<>>, <<>>, <<>>}];
   
    _Other ->
      {error, protocol_violation}
  end;

parse_header(<<1:1, 16#7f:7, Version:4/binary, DCIL:4, SCIL:4,
               Rest/binary>>, 
             #quic_data{
                conn = #quic_conn{
                          dest_conn_ID = undefined,
                          src_conn_ID = undefined
                         } = Conn0
               } = Data0) ->
  %% Initial packet first packet received by server.
  Dest_Len = conn_length(DCIL),
  Src_Len = conn_length(SCIL),

  <<Dest_Conn:Dest_Len/binary, Src_Conn:Src_Len/binary, 
    Payload_Flag:2, Rest1/bits>> = Rest,
  
  Data1 = Data0#quic_data{
            conn = Conn0#quic_conn{
                     dest_conn_ID = Src_Conn,
                     src_conn_ID = Dest_Conn
                    }
           },

  case quic_vxx:supported(Version) of
    {ok, {Module, Version}} ->

      Data2 = Data1#quic_data{
                version = #quic_version{
                             initial_version = Version,
                             negotiated_version = Version
                            },
                vx_module = Module
               },

      Payload_Length = from_var_length(Payload_Flag),
      
      <<Length:Payload_Length/unit:8, Pkt_Num:4/binary, 
        Retry_Token_Flag:2, Rest2/bits>> = Rest1,
      
      Token_Length = from_var_length(Retry_Token_Flag),

      %% Payload_Length is actually 16 bytes greater due to the AEAD Tag.
      <<Token_Size:Token_Length, Retry_Token:Token_Size/binary, Tag:16/binary,
        Payload:Length/binary>> = Rest2,
      
      Header = <<1:1, 16#7f:7, Version/binary, DCIL:4, SCIL:4, 
                 Dest_Conn/binary, Src_Conn/binary, Payload_Flag:2, 
                 Length:Payload_Length>>,
      
      [{initial, Data2, Header, Pkt_Num, Retry_Token, <<Tag/binary, Payload/binary>>}];

    {error, unsupported} ->
      {unsupported, Data1}
  end;

parse_header(<<1:1, 16#7f:7, Version:4/binary, DCIL:4, SCIL:4,
               Rest/binary>>,
             #quic_data{
                conn = #quic_conn{
                          dest_conn_ID = Src_Conn,
                          src_conn_ID = Dest_Conn
                         },
                version = #quic_version{
                             initial_version = Version
                            }
               } = Data) ->
  %% Initial packet when stuff is known.
  Dest_Len = conn_length(DCIL),
  Src_Len = conn_length(SCIL),

  case Rest of
    <<Dest_Conn:Dest_Len/binary, Src_Conn:Src_Len/binary, 
      Payload_Flag:2, Rest1/bits>> ->
      %% The connection id's match.
      
      Payload_Length = from_var_length(Payload_Flag),
      %% Payload_Length is actually 16 bytes greater due to the AEAD Tag.
      %% Retry_Token is a single byte of 0 in all other initial packet cases.
      
      <<Length:Payload_Length/unit:8, Pkt_Num:4/binary, 0:8, Tag:16/binary,
        Payload:Length/binary, Other/binary>> = Rest1,
      
      Header = <<1:1, 16#7f:7, Version/binary, DCIL:4, SCIL:4, 
                 Dest_Conn/binary, Src_Conn/binary, Payload_Flag:2, 
                 Length:Payload_Length>>,
      
      [{initial, Data, Header, Pkt_Num, <<0:8>>, <<Tag/binary, Payload/binary>>} | 
       parse_header(Other, Data)];
    
    _Other ->
      {invalid, protocol_violation}
  end;

parse_header(<<1:1, Type:7, Version:4/binary, DCIL:4, SCIL:4,
               Rest/binary>>,
             #quic_data{
                conn = #quic_conn{
                          dest_conn_ID = Src_Conn,
                          src_conn_ID = Dest_Conn
                         },
                version = #quic_version{
                             initial_version = Version
                            }
               } = Data) ->
  %% Other long packets.
  Dest_Len = conn_length(DCIL),
  Src_Len = conn_length(SCIL),
  
  Type_Atom = 
    case Type of
      16#7e ->
        retry;
      16#7d ->
        handshake;
      16#7c ->
        early_data
    end,

  case Rest of
    <<Dest_Conn:Dest_Len/binary, Src_Conn:Src_Len/binary, 
      Payload_Flag:2, Rest1/bits>> ->
      %% The connection id's match.
      
      Payload_Length = from_var_length(Payload_Flag),
      %% Payload_Length is actually 16 bytes greater due to the AEAD Tag.
      %% Retry_Token is a single byte of 0 in all other initial packet cases.
      
      <<Length:Payload_Length/unit:8, Pkt_Num:4/binary, Tag:16/binary,
        Payload:Length/binary, Other/binary>> = Rest1,
      
      Header = <<1:1, 16#7f:7, Version/binary, DCIL:4, SCIL:4, 
                 Dest_Conn/binary, Src_Conn/binary, Payload_Flag:2, 
                 Length:Payload_Length>>,
      
      [{Type_Atom, Data, Header, Pkt_Num, <<Tag/binary, Payload/binary>>} | 
       parse_header(Other, Data)];
    
    _Other ->
      {invalid, protocol_violation}
  end;

parse_header(<<0:1, _Rest/binary>> = Packet,
             #quic_data{
                conn = #quic_conn{
                          src_conn_ID = Dest_Conn
                         }
               } = Data) ->
  Header_Len = conn_length(Dest_Conn) + 1,
  %% 1 for the one byte type field.
  <<Header:Header_Len/binary, Pkt_Num:4/binary, Payload/binary>> = Packet,

  %% Short packets have to be the last of any coalesced packet.
  [{short, Data, Header, Pkt_Num, Payload}];

parse_header(<<>>, _Data) ->
  %% Base Case for splitting the packets up.
  [].





-spec form_packet(Type, Data) -> Result when
    Type :: retry |
            vx_neg,
    Data :: #quic_data{},
    Result :: {ok, Data, Packet} | {error, Reason},
    Packet :: binary(),
    Reason :: gen_quic:errors().

%% TODO: Update to use #quic_data{}

%% form_packet/2 is used to create retry and vx_neg packets.
%% If the version chosen by the client is not supported,
%% this creates a vx_neg packet from the supported_versions list in version.
%% For retry packets the initial version is used.
form_packet(vx_neg, 
            #quic_data{
               version = #quic_version{
                            supported_versions = Versions
                           }
              } = Data0) ->
  
  ok;

form_packet(retry,
            #quic_data{
               version = #quic_version{
                            initial_version = Version
                           }
              } = Data) ->
  case quic_vxx:supported(Version) of
    {ok, {Module, Version}} ->
      %% Call the version specific module to parse the packet.
      Module:form_packet(retry, Data);
    
    {error, unsupported} ->
      %% Return with unsupported if not supported.
      %% This should probably call vx_neg.
      {error, unsupported};
    
    Other ->
      ?DBG("Error checking header version: ~p~n", [Other]),
      Other
  end.


%% This will be changed to only form payloads of packets.
%% Should be simpler to handle packet encryption in that case.
-spec form_packet(Type, Data, Frames) -> Result when
    Type :: initial |
            early_data |
            handshake |
            short,
    Data :: #quic_data{},
    Frames :: [quic_frame()],
    Result :: {ok, Data, Payload} | {error, Reason},
%%    Header :: binary(),
    Payload :: binary(),
    Reason :: gen_quic:errors().

%% The version is known and agreed upon. We still need to lookup the correct module
%% Somehow this needs to make sure that the initial packet from a client or server
%% has only the information normally sent then.
%% Same for the handshake packets.
form_packet(Type,
            #quic_data{
               version = #quic_version{
                            negotiated_version = Version
                           },
               vx_module = undefined
              } = Data0,
            Frames) ->
  case quic_vxx:supported(Version) of
    {ok, {Module, Version}} ->

      Data = Data0#quic_data{
               vx_module = Module
              },
      
      Module:form_packet(Type, Data, Frames);

    {error, unsupported} ->
      %% Maybe call version negotiate at this point.
      {error, unsupported};

    Other ->
      ?DBG("Error checking header version: ~p~n", [Other]),
      Other
  end;

%% The version_module is already known at this point so we don't need to look it up
form_packet(Type,
            #quic_data{
               vx_module = Module
              } = Data,
            Frames) ->
  Module:form_packet(Type, Data, Frames).


-spec form_header(Type, Data, Payload_Size) -> Header when
    Type :: initial |
            early_data |
            handshake |
            short,
    Data :: #quic_data{},
    Payload_Size :: non_neg_integer(),
    Header :: binary().

form_header(initial, 
            #quic_data{
               conn = #quic_conn{
                         src_conn_ID = Src_ID,
                         dest_conn_ID = Dest_ID
                        },
               version = #quic_version{
                            negotiated_version = Version
                           },
               init_pkt_num = IPN,
               retry_token = Retry_Token
              },
            Payload_Size) ->

  %% For now all packet numbers are 4 bytes.
  %% TODO: Change packet number to variable length.
  Length = to_var_length(Payload_Size + byte_size(Retry_Token) + 4),
  
  Src_Conn_Len = conn_length(Src_ID),
  Dest_Conn_Len = conn_length(Dest_ID),

  <<1:1, 16#7f:7, Version:32, Dest_Conn_Len:4, Src_Conn_Len:4,
    Dest_ID/binary, Src_ID/binary, Length/binary, IPN:4/unit:8,
    Retry_Token/binary>>;

form_header(handshake,
            #quic_data{
               conn = #quic_conn{
                         src_conn_ID = Src_ID,
                         dest_conn_ID = Dest_ID
                        },
               version = #quic_version{
                            negotiated_version = Version
                           },
               hand_pkt_num = HPN
              },
            Payload_Size) ->
  %% For now all packet numbers are 4 bytes.
  %% TODO: Change packet number to variable length.
  Length = to_var_length(Payload_Size + 4),
  
  Src_Conn_Len = conn_length(Src_ID),
  Dest_Conn_Len = conn_length(Dest_ID),

  <<1:1, 16#7d:7, Version:32, Dest_Conn_Len:4, Src_Conn_Len:4,
    Dest_ID/binary, Src_ID/binary, Length/binary, HPN:4/unit:8>>;

form_header(early_data,
            #quic_data{
               conn = #quic_conn{
                         src_conn_ID = Src_ID,
                         dest_conn_ID = Dest_ID
                        },
               version = #quic_version{
                            negotiated_version = Version
                           },
               init_pkt_num = IPN
              },
            Payload_Size) ->

  %% For now all packet numbers are 4 bytes.
  %% TODO: Change packet number to variable length.
  Length = to_var_length(Payload_Size + 4),
  
  Src_Conn_Len = conn_length(Src_ID),
  Dest_Conn_Len = conn_length(Dest_ID),

  <<1:1, 16#7c:7, Version:32, Dest_Conn_Len:4, Src_Conn_Len:4,
    Dest_ID/binary, Src_ID/binary, Length/binary, IPN:4/unit:8>>;

%% TODO: Add key-phase to short packets.
form_header(short,
            #quic_data{
               conn = #quic_conn{
                         dest_conn_ID = Dest_ID
                        },
               app_pkt_num = APN
              },
            _) ->
  
  <<1:1, 0:1, 1:1, 1:1, 0:1, 0:1, 0:1, 0:1, Dest_ID/binary, APN:4/unit:8>>.



%%%%%%%%%%
%%  Internal Functions
%%%%%%%%%%


%% Section 4.1 QUIC Transport
%% Connection ID lengths are increased by 3 if non-zero in length.
%% Allows for an 18 octet connection id to fit into a 4 bit length.
%% Conversely, encoding the length means you decrement by 3 if non-zero in length.
%% Everything else is a failure.
conn_length(<<>>) ->
  0;
conn_length(Conn_ID) when byte_size(Conn_ID) >= 4, byte_size(Conn_ID) =< 18 ->
  byte_size(Conn_ID) - 3.


%% This function is present in many places.
%% Section 7.1 of QUIC.
to_var_length(Num) when Num < 63 ->
  <<0:2, Num:6>>;
to_var_length(Num) when Num < 16383 ->
  <<1:2, Num:14>>;
to_var_length(Num) when Num < 1073741823 ->
  <<2:2, Num:30>>;
to_var_length(Num) ->
  <<3:3, Num:62>>.


from_var_length(Flag) ->
  case Flag of
    0 -> 6;
    1 -> 14;
    2 -> 30;
    3 -> 62
  end.
  
