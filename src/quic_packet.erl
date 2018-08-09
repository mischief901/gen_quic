%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%%  Needs updating to use #quic_data instead of #quic_conn
%%% @end
%%% Created : 16 May 2018 by alex <alex@alex-Lenovo>
%%%-------------------------------------------------------------------
-module(quic_packet).

%% API
-export([parse_packet/2, form_packet/2]).
-export([form_header/3]).

-include("quic_headers.hrl").

%%%===================================================================
%%% API
%%%===================================================================

%% Checks if it is a version negotiation packet. If not, looks up version in quic_vxx
%% If supported, version module parses packet. 
%% Otherwise, returns {error, unsupported}.


-spec parse_packet(Raw_Packet, Data) -> Result when
    Raw_Packet :: binary(),
    Data :: #quic_data{},
    Result :: {ok, Data, Frames, TLS_Frames} | 
              {vx_neg, Versions} |
              {error, Reason},
    Frames :: [quic_frame()],
    TLS_Frames :: #tls_record{},
    Versions :: [version()],
    Reason :: gen_quic:errors().

%% Version Negotiation Packet is not version specific.
parse_packet(<<1:1, _Type:7, 0:32, DCIL:4, SCIL:4,
               Rest/binary>>,
             #quic_data{
                conn = #quic_conn{
                          src_conn_ID = Dest_Conn,
                          dest_conn_ID = Src_Conn
                         }
               }) ->
  %% Make sure the packet has the correct source and destination connection id's.
  Dest_Len = from_conn_length(DCIL),
  Src_Len = from_conn_length(SCIL),
  
  <<Dest:Dest_Len/binary, Src:Src_Len/binary, Vx_Frames/binary>> = Rest,

  case {Dest, Src} of
    {Dest_Conn, Src_Conn} ->
      %% Both match.
      %% All version frames are 32 bits.
      Versions = [ <<Vx/binary>> || <<Vx:32>> <= Vx_Frames ],
      
      {vx_neg, Versions};
    
    _Other ->
      {error, protocol_violation}
  end;

%% First initial packet received by server.
parse_packet(<<1:1, 16#1f:7, Version_Bin:32, DCIL:4, SCIL:4, 
               Rest/binary>> = Packet,
             #quic_data{
                type = server,
                conn = #quic_conn{
                          src_conn_ID = undefined,
                          dest_conn_ID = undefined
                         } = Conn,
                version = #quic_version{
                             version_module = undefined
                            } = Vx,
                crypto = #quic_crypto{
                            state = undefined
                           }
               } = Data0) ->
  %% This is the first packet the server received.
  %% Need to finish parsing header though.
  Dest_Len = from_conn_length(DCIL),
  Src_Len = from_conn_length(SCIL),
  
  <<Dest_Conn:Dest_Len/binary, Src_Conn:Src_Len/binary, _/binary>> = Rest,
  
  Data1 = Data#quic_data{
            conn = Conn0#quic_conn{
                     src_conn_ID = Dest_Conn,
                     dest_conn_ID = Src_Conn
                    }
           },

  %% Lookup version and see if supported.
  case quic_vxx:supported(Version_Bin) of
    {ok, {Module, Version_Bin}} ->
      %% Version is supported for set it.
      Data2 = crypto_init(Data1#quic_data{
                            version = Vx#quic_version{
                                        initial_version = Version_Bin,
                                        negotiated_version = Version_Bin,
                                        version_module = Module
                                       }
                           }),
      %% Recurse and decrypt packet now that everything is initialized
      quic_crypto:parse_packet(Packet, Data2);

    {error, unsupported} ->
      %% Return with unsupported if not supported.     
      {unsupported, Data1};
    
    Other ->
      ?DBG("Error checking header version: ~p~n", [Other]),
      Other
  end;

%% Short header. DCID, SCID, version, and Module are already known.
parse_packet(<<0:1, _Rest/binary>> = Packet, 
             #quic_conn{
                version_mod = Module,
                version = Vx,
                src_conn_ID = DCID,
                dest_conn_ID = SCID
               }) ->

  Packet_Info = #quic_packet{
                   version = Vx,
                   src_conn_ID_len = byte_size(SCID),
                   src_conn_ID = SCID,
                   dest_conn_ID_len = byte_size(DCID),
                   dest_conn_ID = DCID,
                   type = short,
                   long = 0
                  },

  %% Call the parser in the known version module.
  Module:parse_packet(Packet, Packet_Info);

parse_packet(Other, _Unused) ->
  ?DBG("Incorrect format: ~p~n", [Other]),
  {error, badarg}.



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
                            supported_version = Versions
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
    Frames :: [quic_frames()],
    Result :: {ok, Data, Payload} | {error, Reason},
    Header :: binary(),
    Payload :: binary(),
    Reason :: gen_quic:errors().

%% The version is known and agreed upon. We still need to lookup the correct module
%% Somehow this needs to make sure that the initial packet from a client or server
%% has only the information normally sent then.
%% Same for the handshake packets.
form_packet(Type,
            #quic_data{
               version = #quic_version{
                            negotiated_version = Version,
                            version_module = undefined
                           } = Vx,
              } = Data0,
            Frames) ->
  case quic_vxx:supported(Version) of
    {ok, {Module, Version}} ->

      Data = Data0#quic_data{
               version = Vx#quic_version{version_module = Module}
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
               version = #quic_version{
                            version_module = Module
                           } = Vx,
              } = Data,
            Frames) ->
  Module:form_packet(Type, Data, Frames).


-spec form_header(Type, Data, Payload_Size) -> Header when
    Type :: initial |
            early_data |
            handshake |
            short,
    Data :: #quic_data{],
    Payload_Size :: non_neg_integer(),
    Header :: binary().

form_header(initial, 
            #quic_data{
               conn = #quic_conn{
                         src_conn_ID = Src_ID,
                         dest_conn_ID = Dest_ID,
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
    Reset_Token/binary>>;

form_header(handshake,
            #quic_data{
               conn = #quic_conn{
                         src_conn_ID = Src_ID,
                         dest_conn_ID = Dest_ID,
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
                         dest_conn_ID = Dest_ID,
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
                         dest_conn_ID = Dest_ID,
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

  
