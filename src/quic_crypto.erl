%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%% The quic_crypto module is used to decrypt packets after receipt
%%% and encrypt packets prior to transmission. Modules quic_prim and
%%% quic_server both call quic_crypto directly then quic_crypto calls
%%% quic_packet for parsing and encoding of packets. This allows for
%%% a central location for all the cryptographic materials.
%%%
%%% TODO: Potentially move crypto frame parsing into quic_packet so
%%% that the modules do not have a circular dependency on each other.
%%%
%%% I'm not an expert on any of the cryptographic stuff so please
%%% correct any mistakes you find. This should by no means be
%%% considered cryptographically sound.
%%% 
%%% Currently only AES_GCM is supported. Future support for CHACHA20
%%% will eventually happen. Only support for secp256r1, as well, for now.
%%% 
%%% dansarie/tls13 on github was helpful in understanding some of the TLS 1.3
%%% requirements. It will also be helpful for expanding this to other encryption
%%% suites, eventually.
%%% @end
%%% Created : 13 Jul 2018 by alex <alex@alex-Lenovo>

-module(quic_crypto).

-export([default_params/2]).
-export([form_packet/2]).
-export([parse_packet/2]).
-export([parse_crypto_frame/1]).
-export([crypto_init/1]).
-export([rekey/1]).
-export([validate_tls/2]).


-include("quic_headers.hrl").

%% Section 5.1.1 in quic-tls.
%% 0x9c108f98520a5c5c32968e950e8a2c5fe06d6c38 in binary.
%% Used by both the server and client for the initial packet encryption.
%% Should probably move to quic_headers.hrl
-define(INIT_SALT, <<"890971881060553961357831129889474657284229262392">>).

quic_params() ->
  %% Returns a list of keywords for the quic parameters.
  %% Does not include reset_token or preferred_address since only the server
  %% can send those.
  [
   init_max_stream_data,
   init_max_data,
   idle_timeout,
   init_max_bi_streams,
   init_max_uni_streams,
   max_packet_size,
   ack_delay_exp,
   migration
  ].

-spec default_params(Type, Options) -> Result when
    Type :: client | server,
    Options :: gen_quic:options(),
    Result :: {ok, #quic_params{}} | {error, gen_quic:errors()}.

default_params(client, Options) ->
  %% Fold over the quic parameters list and any that exist in Options to a
  %% #quic_params{} record.

  Params = lists:foldl(fun(Item, Param) ->
                           case lists:keyfind(Item, 1, Options) of
                             false ->
                               Param;
                             {Item, Value} ->
                               add_param(Param, Item, Value)
                           end
                       end, #quic_params{}, quic_params()),
  {ok, Params};

default_params(server, Options) ->
  %% Fold over the quic parameters list and any that exist in Options to a
  %% #quic_params{} record.

  Params = lists:foldl(fun(Item, Param) ->
                           case lists:keyfind(Item, 1, Options) of
                             false ->
                               Param;
                             {Item, Value} ->
                               add_param(Param, Item, Value)
                           end
                       end, #quic_params{}, 
                       [reset_token, preferred_address | quic_params()]),
  {ok, Params}.

%% This function exists because records are not dynamic and as such values cannot
%% be added in the function above. Probably will move to maps at some point.
%% TODO: Add option validation here. Might work better as an inline case.
add_param(Param, reset_token, Token) ->
  Param#quic_params{reset_token = Token};

add_param(Param, preferred_address, Address) ->
  Param#quic_params{preferred_address = Address};

add_param(Param, init_max_stream_data, Data) ->
  Param#quic_params{init_max_stream_data = Data};

add_param(Param, init_max_data, Data) ->
  Param#quic_params{init_max_data = Data};

add_param(Param, idle_timeout, Timeout) ->
  Param#quic_params{idle_timeout = Timeout};

add_param(Param, init_max_bi_streams, Streams) ->
  Param#quic_params{init_max_bi_streams = Streams};

add_param(Param, init_max_uni_streams, Streams) ->
  Param#quic_params{init_max_uni_streams = Streams};

add_param(Param, max_packet_size, Size) ->
  Param#quic_params{max_packet_size = Size};

add_param(Param, ack_delay_exp, Delay) ->
  Param#quic_params{ack_delay_exp = Delay};

add_param(Param, migration, Bool) ->
  Param#quic_params{migration = Bool}.


-spec crypto_init(Data) -> Data when
    Data :: #quic_data{}.
%% Initializes the client and server initial keying materials
crypto_init(#quic_data{
               type = server,
               conn = #quic_conn{
                         src_conn_ID = Conn_ID
                        }
              } = Data) ->
  set_initial(Data, Conn_ID);

crypto_init(#quic_data{
               type = client,
               conn = #quic_conn{
                         dest_conn_ID = Conn_ID
                        }
              } = Data) ->
  set_initial(Data, Conn_ID).


-spec set_initial(Data, Conn_ID) -> Data when
    Data :: #quic_data{},
    Conn_ID :: binary().

%% Sets the initial secrets for both clients and servers.
set_initial(#quic_data{
               crypto = Crypto0
              } = Data,
            Conn_ID) ->
  
  %% The connection id of the client is the source connection id.
  Init_Secret = initial_extract(Conn_ID),
  Client_Secret = derive_secret(client_initial, Init_Secret, <<0:32/unit:8>>),
  Server_Secret = derive_secret(server_initial, Init_Secret, <<0:32/unit:8>>),
  Pkt_Num_Secret = derive_secret(packet_num, Init_Secret, <<0:32/unit:8>>),

  Crypto = Crypto0#quic_crypto{
             state = initial,
             init_secret = Init_Secret,
             pkt_num_init_secret = Pkt_Num_Secret,
             client_init_secret = Client_Secret,
             server_init_secret = Server_Secret
            },
  set_pub_key(Data#quic_data{crypto = Crypto}).

-spec set_pub_key(Data) -> Data when
    Data :: #quic_data{}.
%% sets the public key from the cert or generates an ephemeral public/private key pair.
%% TODO: Expand to other key groups
set_pub_key(#quic_data{
               %%type = client,
               crypto = #quic_crypto{
                           pub_key = undefined,
                           priv_key = undefined
                          } = Crypto0
              } = Data0) ->
  %% The cert private key is not set so generate an ephemeral pair of keys.
  %% This can only happen with clients, but for now allowed for either
  {Pub_Key, Priv_Key} = gen_key(),
  Data0#quic_data{crypto = Crypto0#quic_crypto{pub_key = Pub_Key, priv_key = Priv_Key}};

set_pub_key(#quic_data{
               crypto = #quic_crypto{
                           pub_key = undefined,
                           priv_key = Priv_Key
                          } = Crypto0
              } = Data0) ->
  %% The cert key is set so generate a public key from the private key.
  {Pub_Key, Priv_Key} = gen_key(Priv_Key),
  Data0#quic_data{crypto = Crypto0#quic_crypto{pub_key = Pub_Key}};

set_pub_key(Data) ->
  %% The public key is already defined, so it doesn't need to be set.
  Data.


-spec validate_tls(Data, TLS_Info) -> Result when
    Data :: #quic_data{},
    TLS_Info :: #tls_record{},
    Result :: {valid, Data} | 
              {incomplete, Data} |
              {invalid, Reason},
    Reason :: term().
%% TODO: Update error Reason type to something more descriptive.

%% This function validates the received tls message and updates quic_data with
%% the given information.

%% Validate_tls does not perform rekeys from the data.
%% rekeying is performed per section 4.1.3 of Quic-TLS in the rekey function.

%% When valid or incomplete the transcript is added to quic_data, except when the
%% stream offset indicates the packet is a repeat.
%% If validation is successful, {valid, NewData} is returned and NewData should
%% be passed into the correct rekey function.
%% If TLS step is incomplete, {incomplete, NewData} is returned and the keys
%% should remain the same until more information is received.
%% If the tls info is invalid, the connection should be cancelled.
%% TODO: send tls error back to other side of connection.


%% TODO: Add check for crypto offset to make sure that the crypto stream is
%% in order and valid.

validate_tls(#quic_data{
                crypto = #quic_crypto{
                            state = initial,
                            init_offsets = {_Send, Offset}
                           }
               } = Data,
             #tls_record{
                offset = TLS_Offset
               }) when TLS_Offset =< Offset ->
  %% Probably a repeated packet
  %% Just return {incomplete, Data} since it keeps state
  %% and waits for the next packet.
  {incomplete, Data};


validate_tls(#quic_data{
                crypto = #quic_crypto{
                            state = protected,
                            protected_offsets = {_Send, Offset}
                           }
               } = Data,
             #tls_record{
                offset = TLS_Offset
               }) when TLS_Offset =< Offset ->
  %% Probably a repeated packet
  %% Just return {incomplete, Data} since it keeps state
  %% and waits for the next packet.
  {incomplete, Data};


validate_tls(#quic_data{
                crypto = #quic_crypto{
                            state = handshake,
                            handshake_offsets = {_Send, Offset}
                           }
               } = Data,
             #tls_record{
                offset = TLS_Offset
               }) when TLS_Offset =< Offset ->
  %% Probably a repeated packet
  %% Just return {incomplete, Data} since it keeps state
  %% and waits for the next packet.
  {incomplete, Data};


validate_tls(#quic_data{
                crypto = #quic_crypto{
                            state = initial,
                            init_offsets = {_Send, Offset}
                           }
               },
             #tls_record{
                offset = TLS_Offset
               } = Record) when TLS_Offset > Offset + 1 ->
  %% Missing a packet
  {out_of_order, {TLS_Offset, Record}};


validate_tls(#quic_data{
                crypto = #quic_crypto{
                            state = protected,
                            protected_offsets = {_Send, Offset}
                           }
               },
             #tls_record{
                offset = TLS_Offset
               } = Record) when TLS_Offset > Offset + 1 ->
  %% Missing a packet
  {out_of_order, {TLS_Offset, Record}};

validate_tls(#quic_data{
                crypto = #quic_crypto{
                            state = handshake,
                            handshake_offsets = {_Send, Offset}
                           }
               },
             #tls_record{
                offset = TLS_Offset
               } = Record) when TLS_Offset > Offset + 1 ->
  %% Missing a packet
  {out_of_order, {TLS_Offset, Record}};


validate_tls(#quic_data{
                type = server,
                version = #quic_version{
                             negotiated_version = Version
                             %% Negotiated version is set from the initial header.
                            },
                crypto = #quic_crypto{
                            state = initial,
                            transcript = Transcript,
                            init_offsets = {_Send, _Recv}
                           } = Crypto0
               } = Data0,
             
             #tls_record{
                legacy_version = 16#0303,
                %% Must be 0x0303
                type = client_hello,
                quic_version = Version,
                %% Version specified in the quic extension must match that of header and
                %% must be supported by server.
                tls_supported_versions = TLS_Versions0,
                %% The tls versions supplied by client must have one that is TLS1.3
                cipher_suites = Ciphers,
                signature_algs = Sign_Algs,
                key_share = Key_Shares,
                groups = Groups,
                quic_params = Params,
                temp_bin = Trans_Message,
                offset = TLS_Offset
               }) ->

  %% The server should receive a client_hello message when in the initial crypto state.
  %% The client_hello is valid if it contains a Cipher, Signature Algorithm,
  %% Key Share, and Quic Params extensions and versions match.
  %% Versions match in this function clause.
  %% Only returns valid or invalid since the entire client_hello must fit in one
  %% crypto frame and quic packet.

  %% TODO: Have filter apply to newer versions of TLS.
  TLS_Versions = lists:filter(fun(Ver) -> Ver == 16#0304 end,
                              TLS_Versions0),

  %% Check that a cipher is valid and a signature is valid.
  %% TODO: Add valid_group check.
  case {TLS_Versions, valid_cipher(Ciphers), 
        valid_signature(Sign_Algs), valid_group(Groups)} of
    
    {[], _, _, _} ->
      {invalid, tls_version};
    
    {_, false, _, _} ->
      %% TODO: Needs better error.
      {invalid, no_cipher};

    {_, _, false, _} ->
      %% TODO: Needs better error.
      {invalid, no_signature_alg};
    
    {_, _, _, false} ->
      %% TODO: Needs better error.
      {invalid, no_group};
    
    {TLS_Version, Cipher, Sign_Alg, Group} ->
      %% Success. First from each that is supported is chosen in the valid_* funs.
      %% Need to check for key_share.
      %% TODO: Add check for empty key_share.
      {Group, Other_Pub_Key} = lists:keyfind(Group, 1, Key_Shares),

      case valid_params(Params) of
        true ->
          %% Everything is valid so derive secrets and return Data.
          
          Data = Data0#quic_data{
                   crypto = Crypto0#quic_crypto{
                              tls_version = TLS_Version,
                              group = Group,
                              cipher = Cipher,
                              signature_alg = Sign_Alg,
                              other_pub_key = Other_Pub_Key,
                              transcript = <<Transcript/binary, Trans_Message/binary>>,
                              init_offsets = {_Send, TLS_Offset}
                             },
                   params = Params
                  },
          {valid, Data};
        
        _Other ->
          %% Invalid quic parameters
          %% This should lead to a retry packet, I think
          {invalid, Params}
      end
  end;

validate_tls(#quic_data{
                type = client,
                crypto = #quic_crypto{
                            state = initial,
                            transcript = Transcript,
                            init_offsets = {_Send, _Recv}
                           } = Crypto0
               } = Data0,
             
             #tls_record{
                legacy_version = 16#0303,
                %% Must be 0x0303
                type = server_hello,
                tls_supported_versions = 16#0304,
                %% The tls version must be supported.
                cipher_suites = Ciphers,
                key_share = [{Group, Pub_Key}],
                temp_bin = Trans_Message,
                offset = TLS_Offset
               }) ->
  %% Needs to check that a valid cipher_suite and key_share group is supplied
  case {valid_cipher(Ciphers), valid_group([Group])} of
    {false, _} ->
      {invalid, no_cipher};

    {_, false} ->
      {invalid, key_share};

    {Cipher, Group} -> 
      %% Valid cipher was chosen.
      %% Singular key_share was chosen.

      Data = Data0#quic_data{
               crypto = Crypto0#quic_crypto{
                          state = handshake,
                          transcript = <<Transcript/binary, Trans_Message/binary>>,
                          cipher = Cipher,
                          other_pub_key = Pub_Key,
                          group = Group,
                          init_offsets = {_Send, TLS_Offset}
                         }},
      {valid, Data}
  end;

validate_tls(#quic_data{
                type = client,
                version = Version,
                crypto = #quic_crypto{
                            transcript = Transcript,
                            state = handshake,
                            handshake_offsets = {_Send, _Recv}
                           }= Crypto0
               } = Data0,
             
             #tls_record{
                type = encrypted_exts,
                quic_version = Version,
%%                other_quic_versions = Quic_Versions, Unused right now.
                signature_algs = Sign_Algs,
                groups = Groups,
                quic_params = Params,
                temp_bin = Trans_Message,
                offset = TLS_Offset
               }) ->
  %% Need to check the versions match, a valid signature alg is chosen,
  %% a group, and quic params.

  case {valid_signature(Sign_Algs), valid_group(Groups)} of
    {false, _} ->
      {invalid, no_signature_alg};

    {_, false} ->
      {invalid, no_group};

    {Sign_Alg, Group} ->
      %% Success case.
      %% TODO: Maybe move to above case statement.
      case valid_params(Params) of
        true ->
          Data = Data0#quic_data{
                   params = Params,
                   crypto = Crypto0#quic_crypto{
                              group = Group,
                              signature_alg = Sign_Alg,
                              transcript = <<Transcript/binary, Trans_Message/binary>>,
                              handshake_offsets = {_Send, TLS_Offset}
                             }},
          {incomplete, Data};
        
        false ->
          {invalid, Params}
      end
  end;

validate_tls(#quic_data{
                type = client,
                crypto = #quic_crypto{
                            state = handshake,
                            transcript = Transcript,
                            other_pub_key = Pub_Key,
                            handshake_offsets = {_Send, _Recv}
                           } = Crypto0
               } = Data0,

             #tls_record{
                type = certificate,
                root_cert = Trusted_Cert,
                cert_chain = Certs,
                peer_cert = Peer_Cert,
                temp_bin = Trans_Message,
                offset = TLS_Offset
               }) ->
  %% TODO: This should contain the server's cert message.
  %% Need to validate that the Peer_Cert is authorized by the Cert Chain
  %% This needs to be checked against other examples / verified.
  %% For now self signed certs are valid.
  case public_key:pkix_verify(Peer_Cert, Pub_Key) of
    true ->
      %% The Peer Cert is valid.

      %% Allow for selfsigned certs.
      Self_Sign = fun(_, {bad_cert, selfsigned_peer}, State) ->
                      {valid, State};
                     (_, valid, State) ->
                      {valid, State}
                  end,

      case public_key:pkix_path_validation(Trusted_Cert, Certs, 
                                           [{verify_fun, Self_Sign}]) of
        
        {ok, _} ->
          %% Everything is valid or self-signed.
          Data = Data0#quic_data{
                   crypto = Crypto0#quic_crypto{
                              handshake_offsets = {_Send, TLS_Offset},
                              transcript = <<Transcript/binary, Trans_Message/binary>>
                             }},
          {incomplete, Data};

        {error, Reason} ->
          {invalid, Reason}
      end;

    false ->
      %% Primary Cert is not valid
      {invalid, cert}
  end;

validate_tls(#quic_data{
                type = client,
                crypto = #quic_crypto{
                            state = handshake,
                            transcript = Transcript,
                            signature_alg = Sign_Alg,
                            other_pub_key = Pub_Key,
                            handshake_offsets = {_Send, _Recv}
                           } = Crypto0
               } = Data0,

             #tls_record{
                type = cert_verify,
                signature = Signature,
                signature_algs = [Sign_Alg],
                offset = TLS_Offset,
                temp_bin = Trans_Message
               }) ->
  %% Signature algs must match.
  %% TODO: This should contain the server's certificate verify message.
  %% Needs to verify the transcript hash of messages including the certificate with
  %% that in the certificate verify signature.
  {Sign, Params, Hash} = Sign_Alg,

  Digest = crypto:hash(sha256, Transcript),

  case crypto:verify(Sign, Hash, {digest, Digest}, Signature, [Pub_Key, Params]) of
    true ->
      %% Cert Verify was accurate

      Data = Data0#quic_data{
               crypto = Crypto0#quic_crypto{
                          transcript = <<Transcript/binary, Trans_Message/binary>>,
                          handshake_offsets = {_Send, TLS_Offset}
                         }},
      {valid, Data};

    _Other ->
      %% The cert verify was not accurate
      {invalid, cert_verify}
  end;

validate_tls(#quic_data{
                type = client,
                crypto = #quic_crypto{
                            state = handshake,
                            transcript = Transcript,
                            server_handshake_secret = Server_Secret,
                            handshake_offsets = {_Send, _Recv}
                           } = Crypto0
               } = Data0,

             #tls_record{
                type = finished,
                cert_verify = Fin_Verify,
                offset = TLS_Offset,
                temp_bin = Trans_Message
               }) ->
  %% TODO: This should contain server's finished message.
  %% Needs to check the Fin_Verify data against the expected value of Fin_Verify

  Fin_Key = derive_secret(finished, Server_Secret, <<>>),
  
  Trans_Hash = crypto:hash(sha256, Transcript),

  case crypto:hmac(sha256, Fin_Key, Trans_Hash) of
    
    Fin_Verify ->
      %% Successful
      
      Data0#quic_data{
        crypto = Crypto0#quic_crypto{
                   transcript = <<Transcript/binary, Trans_Message/binary>>,
                   handshake_offsets = {_Send, TLS_Offset}
                  }};

    _Other ->
      {invalid, finished}
  end;

validate_tls(#quic_data{
                type = server,
                crypto = #quic_crypto{
                            state = protected,
                            transcript = Transcript,
                            client_handshake_secret = Client_Secret,
                            handshake_offsets = {_Send, _Recv}
                           } = Crypto0
               } = Data0,

             #tls_record{
                type = finished,
                cert_verify = Fin_Verify,
                offset = TLS_Offset
               }) ->
  %% TODO: This should contain the client's finished message.
  %% Same as above. Might be able to combine them.
  %% TODO: This should contain server's finished message.
  %% Needs to check the Fin_Verify data against the expected value of Fin_Verify

  Key = derive_secret(finished, Client_Secret, <<>>),
  
  Trans_Hash = crypto:hash(sha256, Transcript),

  case crypto:hmac(sha256, Key, Trans_Hash) of
    
    Fin_Verify ->
      %% Successful
            
      Data = Data0#quic_data{
               crypto = Crypto0#quic_crypto{
                          transcript = undefined,
                          %% Not needed anymore. If resumption master secret was a goal
                          %% This would be needed and updated.
                          handshake_offsets = {_Send, TLS_Offset}
                         }},
      {valid, Data};

    _Other ->
      {invalid, finished}
  end.


%% Maybe add a finished state to this for the fin verify data.

-spec rekey(Data) -> Data when
    Data :: #quic_data{}.

%% This clause rekeys the server/client to the handshake level
rekey(#quic_data{
         crypto = #quic_crypto{
                     state = initial,
                     init_secret = Init_Secret,
                     priv_key = Priv_Key,
                     other_pub_key = Other_Pub_Key,
                     transcript = Transcript
                    } = Crypto0
        } = Data0) ->
  %% Derive common secret from Init secret and Shared Secret
  Shared_Secret = shared_secret(Other_Pub_Key, Priv_Key),
  %% Transcript should include Client_Hello and Server_Hello at this point.
  Trans_Hash = crypto:hash(sha256, Transcript),
  
  HS_Key = derive_secret(derived, Init_Secret, <<>>),
  HS_Secret = extract(HS_Key, Shared_Secret),

  Client_HS_Secret = derive_secret(client_hs, HS_Secret, Trans_Hash),
  Server_HS_Secret = derive_secret(server_hs, HS_Secret, Trans_Hash),
  Pkt_Num_HS_Secret = derive_secret(pkt_num, HS_Secret, Trans_Hash),
  
  {Client_Key, Client_IV} = expand(keys, Client_HS_Secret),
  {Server_Key, Server_IV} = expand(keys, Server_HS_Secret),

  Data0#quic_data{
    crypto = Crypto0#quic_crypto{
               state = handshake,
               handshake_secret = HS_Secret,
               client_handshake_secret = Client_HS_Secret,
               server_handshake_secret = Server_HS_Secret,
               client_handshake_key = Client_Key,
               client_handshake_iv = Client_IV,
               server_handshake_key = Server_Key,
               server_handshake_iv = Server_IV,
               pkt_num_handshake_secret = Pkt_Num_HS_Secret
              }};

%% rekey to protected encryption level.
rekey(#quic_data{
         crypto = #quic_crypto{
                     state = handshake,
                     handshake_secret = HS_Secret,
                     transcript = Transcript
                    } = Crypto0
        } = Data0) ->

  %% This should include all the messages except the Client Finished.
  Trans_Hash = crypto:hash(sha256, Transcript),

  Protected_Key = derive_secret(derived, HS_Secret, <<>>),
  Protected_Secret = extract(Protected_Key, <<0:32/unit:8>>),

  Client_Protected_Secret = derive_secret(client_ap, Protected_Secret, Trans_Hash),
  Server_Protected_Secret = derive_secret(server_ap, Protected_Secret, Trans_Hash),
  Packet_Num_Secret = derive_secret(packet_num, Protected_Secret, Trans_Hash),
  
  {Client_Key, Client_IV} = expand(keys, Client_Protected_Secret),
  {Server_Key, Server_IV} = expand(keys,Server_Protected_Secret),

  Data0#quic_data{
    crypto = Crypto0#quic_crypto{
               state = protected,
               protected_secret = Protected_Secret,
               client_protected_secret = Client_Protected_Secret,
               server_protected_secret = Server_Protected_Secret,
               pkt_num_protected_secret = Packet_Num_Secret,
               server_protected_key = Server_Key,
               server_protected_iv = Server_IV,
               client_protected_key = Client_Key,
               client_protected_iv = Client_IV
              }}.

      
-spec form_packet(Type, Data) -> Result when
    Type :: initial |
            handshake |
            protected |
            vx_neg |
            retry,
    Data :: #quic_data{},
    Result :: {ok, Data, Packet} |
              {error, Reason},
    Packet :: binary(),
    Reason :: gen_quic:errors().
%% form_packet creates an encrypted long header packet and updates the 
%% packet number and other fields for the corresponding type in Data.
%% form_packet/2 does not encode any additional data into frames and is
%% only used for crypto frame transportation.
%% form_packet/3 does allow for encoding other frame data.
form_packet(vx_neg, Data) ->
  %% Version Negotiation packets are not encrypted so just pass through to quic_packet.
  quic_packet:form_packet(vx_neg, Data);

form_packet(retry, Data) ->
  %% retry packets are not encrypted so just pass through to quic_packet.
  quic_packet:form_packet(retry, Data);

form_packet(initial,
            #quic_data{
               type = client,
               init_pkt_num = IPN,
               crypto = #quic_crypto{
                           init_offsets = {Send, _Recv},
                           client_init_iv = Client_IV,
                           client_init_key = Client_Key,
                           pkt_num_init_secret = Pkt_Num_Secret,
                           transcript = Transcript0
                          } = Crypto0,
               retry_token = Reset_Token0
              } = Data0) ->
  %% We first encode the client hello from #quic_data{}
  %% This also wraps the client hello in a quic crypto frame.
  Client_Hello = client_hello(Data0),
  
  %% Add the Client_Hello to the Transcript.
  Transcript = <<Transcript0/binary, Client_Hello/binary>>,

  %% Wrap the client_hello in a crypto frame.
  Offset = to_var_length(Send),
  Length = to_var_length(byte_size(Client_Hello)),
  Crypto_Hello = <<16#18:8, Offset/binary, Length/binary, Client_Hello/binary>>,

  %% Unencrypted packet number is used for the nonce.
  Nonce = get_nonce(IPN, Client_IV),

  %% TODO: It makes sense to have the retry_token set as a binary when it is
  %%       added to #quic_data{} instead of converting it here.  
  Reset_Token =
    case Reset_Token0 of
      undefined ->
        <<0:8>>;
      
      Token ->
        Token_Len = to_var_length(byte_size(Token)),
        <<Token_Len/binary, Token/binary>>
    end,

  %% TODO: Move to separate function
  Padded = if
             byte_size(Crypto_Hello) >= 1200 ->
               Crypto_Hello;
             
             true ->
               Pad_Len = 1200 - byte_size(Crypto_Hello),
               <<Crypto_Hello/binary, 0:Pad_Len/unit:8>>
           end,

  %% This function needs to be updated in quic_packet.
  {ok, Header0} = quic_packet:form_header(initial, Data, byte_size(Padded)),
  
  %% Add the Reset Token to the header
  Header = <<Header0/binary, Reset_Token/binary>>,

  %% Encrypt the packet.
  {Enc_Init, Tag} = encrypt(Padded, Client_Key, Nonce, Header),
  
  %% Encode the packet number using the packet_num_init_secret and AEAD Tag.
  Enc_Pkt_Num = encrypt_pkt_num(IPN, Pkt_Num_Secret, Tag),
  
  %% Update Data.
  Data = Data0#quic_data{
           init_pkt_num = IPN + 1,
           crypto = Crypto0#quic_crypto{
                      transcript = Transcript,
                      init_offsets = {Send + byte_size(Client_Hello) + 1, _Recv}
                     }
          },
  
  %% Remove the unencoded packet number and replace.
  Head_Len = byte_size(Header) - byte_size(Reset_Token) - 4,
  <<Header1:Head_Len/binary, _/binary>> = Header,
  
  %% Add the encoded packet number and Reset Token back.
  Init_Packet = <<Header1/binary, Enc_Pkt_Num/binary, Reset_Token/binary, 
                  Tag/binary, Enc_Init/binary>>,

  {ok, Data, Init_Packet};  

form_packet(initial,
            #quic_data{
               type = server,
               init_ack = Ack0,
               init_pkt_num = IPN,
               crypto = #quic_crypto{
                           pkt_num_init_secret = Pkt_Num_Secret,
                           server_init_iv = Init_IV,
                           server_init_key = Init_Key,
                           transcript = Transcript0,
                           init_offsets = {Send, _Recv}
                          } = Crypto0
              } = Data0) ->
  %% We first encode the server hello from #quic_data{}
  %% This needs to be wrapped in a crypto frame, but first we need to add 
  %% it to the transcript
  Server_Hello = server_hello(Data0),
  %% Transcript should be client_hello and server_hello messages after this.
  Transcript = <<Transcript0/binary, Server_Hello/binary>>,

  %% TODO: Move to separate function.
  Offset = to_var_length(Send),
  Length = to_var_length(byte_size(Server_Hello)),
  Crypto_Hello = <<16#18:8, Offset/binary, Length/binary, Server_Hello/binary>>,

  %% Add acknowledgement(s) to packet.
  %% TODO: ack_frame function
  {Ack_Frame, Ack} = quic_packet:to_ack_frame(Ack0),
  Init_Payload = <<Crypto_Hello/binary, Ack_Frame/binary>>,

  %% Unencrypted packet number is used for the nonce.
  Nonce = get_nonce(IPN, Init_IV),
  
  %% This function needs to be updated in quic_packet.
  Header0 = quic_packet:form_header(initial, Data0, byte_size(Init_Payload)),
  
  %% "Initial packets sent by the server MUST include a zero-length token."
  %% Section 4.4.1 of QUIC.
  %% This value is not included in Header0.
  Header = <<Header0/binary, 0:8>>,

  %% Encrypt the packet.
  {Enc_Frames, Tag} = encrypt(Init_Payload, Init_Key, Nonce, Header),
  
  %% Encode the packet number using the packet_num_init_secret and AEAD Tag.
  Enc_Pkt_Num = encrypt_pkt_num(IPN, Pkt_Num_Secret, Tag),
  
  %% Increment the packet number and update acks. I don't think anything else changes.
  Data = Data0#quic_data{
           init_pkt_num = IPN + 1,
           init_ack = Ack,
           crypto = Crypto0#quic_crypto{
                      transcript = Transcript,
                      init_offsets = {Send + byte_size(Server_Hello) + 1, _Recv}
                     }
          },
  
  %% Remove the unencoded packet number and replace.
  Head_Len = byte_size(Header) - 5,
  <<Header1:Head_Len/binary, _Rest/binary>> = Header,
  
  %% Add the Encoded packet number and re-add the empty token byte.
  Initial = <<Header1/binary, Enc_Pkt_Num:4/binary, 0:8,
              Tag/binary, Enc_Frames/binary>>,
  
  {ok, Data, Initial};

form_packet(encrypted_exts, 
            #quic_data{
               type = server,
               hand_ack = Ack0,
               hand_pkt_num = HPN,
               crypto = #quic_crypto{
                           state = handshake,
                           pkt_num_handshake_secret = Pkt_Num_Secret,
                           server_handshake_key = Handshake_Key,
                           server_handshake_iv = Handshake_IV,
                           transcript = Transcript0,
                           handshake_offsets = {Send, _Recv}
                          } = Crypto0
              } = Data0) ->
  %% Form Encrypted Extensions packet.
  
  Exts = encrypted_exts(Data0),
  
  %% Add it to the transcript
  Transcript = <<Transcript0/binary, Exts/binary>>,
  
  %% Wrap in a crypto frame
  Offset = to_var_length(Send),
  Length = to_var_length(byte_size(Exts)),
  Crypto_Ext = <<16#18:8, Offset/binary, Length/binary, Exts/binary>>,
  
  %% Add any acks: Probably empty.
  {Ack_Frames, Ack} = quic_packet:to_ack_frame(Ack0),
  Handshake_Payload = <<Crypto_Ext/binary, Ack_Frames/binary>>,
  
  %% Create the nonce.
  Nonce = get_nonce(HPN, Handshake_IV),
  
  Header0 = quic_packet:form_header(handshake, Data0, byte_size(Handshake_Payload)),
  
  %% Encrypt the Packet
  {Enc_Frames, Tag} = encrypt(Handshake_Payload, Handshake_Key, Nonce, Header0),
  
  %% Encode the packet number
  Enc_Pkt_Num = encrypt_pkt_num(HPN, Pkt_Num_Secret, Tag),
  
  %% Update Data
  Data = Data0#quic_data{
           hand_pkt_num = HPN + 1,
           hand_ack = Ack,
           crypto = Crypto0#quic_crypto{
                      transcript = Transcript,
                      handshake_offsets = {Send + byte_size(Exts) + 1, _Recv}
                     }
          },
  
  %% Replace the packet number
  Head_Len = byte_size(Header0),
  <<Header:Head_Len/binary, _Rest/binary>> = Header0,
  
  {ok, Data, <<Header/binary, Enc_Pkt_Num/binary, Tag/binary, Enc_Frames/binary>>};

form_packet(certificate,
            #quic_data{
               type = server,
               hand_ack = Ack0,
               hand_pkt_num = HPN,
               crypto = #quic_crypto{
                           state = handshake,
                           pkt_num_handshake_secret = Pkt_Num_Secret,
                           server_handshake_key = Handshake_Key,
                           server_handshake_iv = Handshake_IV,
                           transcript = Transcript0,
                           handshake_offsets = {Send, _Recv},
                           cert = Cert,
                           cert_chain = Cert_Chain
                          } = Crypto0
              } = Data0) ->
  %% Creates the certificate handshake packet.

  Certificate = encode_tls_cert(server, Cert_Chain, Cert),
  
  %% Add it to the transcript
  Transcript = <<Transcript0/binary, Certificate/binary>>,
  
  %% Wrap in a crypto frame
  Offset = to_var_length(Send),
  Length = to_var_length(byte_size(Certificate)),
  Crypto_Cert = <<16#18:8, Offset/binary, Length/binary, Certificate/binary>>,
  
  %% Add any acks: Probably empty.
  {Ack_Frames, Ack} = quic_packet:to_ack_frame(Ack0),
  Handshake_Payload = <<Crypto_Cert/binary, Ack_Frames/binary>>,
  
  %% Create the nonce.
  Nonce = get_nonce(HPN, Handshake_IV),
  
  Header0 = quic_packet:form_header(handshake, Data0, byte_size(Handshake_Payload)),
  
  %% Encrypt the Packet
  {Enc_Frames, Tag} = encrypt(Handshake_Payload, Handshake_Key, Nonce, Header0),
  
  %% Encode the packet number
  Enc_Pkt_Num = encrypt_pkt_num(HPN, Pkt_Num_Secret, Tag),
  
  %% Update Data
  Data = Data0#quic_data{
           hand_pkt_num = HPN + 1,
           hand_ack = Ack,
           crypto = Crypto0#quic_crypto{
                      transcript = Transcript,
                      handshake_offsets = {Send + byte_size(Certificate) + 1, _Recv}
                     }
          },
  
  %% Replace the packet number
  Head_Len = byte_size(Header0),
  <<Header:Head_Len/binary, _Rest/binary>> = Header0,
  
  {ok, Data, <<Header/binary, Enc_Pkt_Num/binary, Tag/binary, Enc_Frames/binary>>};

form_packet(cert_verify,
            #quic_data{
               type = server,
               hand_ack = Ack0,
               hand_pkt_num = HPN,
               crypto = #quic_crypto{
                           state = handshake,
                           pkt_num_handshake_secret = Pkt_Num_Secret,
                           server_handshake_key = Handshake_Key,
                           server_handshake_iv = Handshake_IV,
                           transcript = Transcript0,
                           handshake_offsets = {Send, _Recv}
                          } = Crypto0
              } = Data0) ->
  
  %% Creates the cert verify handshake packet.

  Cert_Verify = encode_tls_cert_verify(server, Data0),
  
  %% Add it to the transcript
  Transcript = <<Transcript0/binary, Cert_Verify/binary>>,
  
  %% Wrap in a crypto frame
  Offset = to_var_length(Send),
  Length = to_var_length(byte_size(Cert_Verify)),
  Crypto_Cert = <<16#18:8, Offset/binary, Length/binary, Cert_Verify/binary>>,
  
  %% Add any acks: Probably empty.
  {Ack_Frames, Ack} = quic_packet:to_ack_frame(Ack0),
  Handshake_Payload = <<Crypto_Cert/binary, Ack_Frames/binary>>,
  
  %% Create the nonce.
  Nonce = get_nonce(HPN, Handshake_IV),
  
  Header0 = quic_packet:form_header(handshake, Data0, byte_size(Handshake_Payload)),
  
  %% Encrypt the Packet
  {Enc_Frames, Tag} = encrypt(Handshake_Payload, Handshake_Key, Nonce, Header0),
  
  %% Encrypt the packet number
  Enc_Pkt_Num = encrypt_pkt_num(HPN, Pkt_Num_Secret, Tag),
  
  %% Update Data
  Data = Data0#quic_data{
           hand_pkt_num = HPN + 1,
           hand_ack = Ack,
           crypto = Crypto0#quic_crypto{
                      transcript = Transcript,
                      handshake_offsets = {Send + byte_size(Cert_Verify) + 1, _Recv}
                     }
          },
  
  %% Replace the packet number with encrypted.
  Head_Len = byte_size(Header0),
  <<Header:Head_Len/binary, _Rest/binary>> = Header0,
  
  {ok, Data, <<Header/binary, Enc_Pkt_Num/binary, Tag/binary, Enc_Frames/binary>>};

form_packet(finished,
            #quic_data{
               type = server,
               hand_ack = Ack0,
               hand_pkt_num = HPN,
               crypto = #quic_crypto{
                           state = handshake,
                           server_handshake_secret = Server_HS_Secret,
                           server_handshake_key = Handshake_Key,
                           server_handshake_iv = Handshake_IV,
                           pkt_num_handshake_secret = Pkt_Num_Secret,
                           transcript = Transcript0,
                           handshake_offsets = {Send, _Recv}
                          } = Crypto0
              } = Data0) ->
  
  %% Creates the tls server finished packet.

  %% First the finished key has to be derived.
  Fin_Key = derive_secret(finished, Server_HS_Secret, <<>>),

  Fin = encode_tls_fin(Fin_Key, Transcript0),
  
  %% Add it to the transcript
  Transcript = <<Transcript0/binary, Fin/binary>>,
  
  %% Wrap in a crypto frame
  Offset = to_var_length(Send),
  Length = to_var_length(byte_size(Fin)),
  Crypto_Fin = <<16#18:8, Offset/binary, Length/binary, Fin/binary>>,
  
  %% Add any acks: Probably empty.
  {Ack_Frames, Ack} = quic_packet:to_ack_frame(Ack0),
  Handshake_Payload = <<Crypto_Fin/binary, Ack_Frames/binary>>,
  
  %% Create the nonce.
  Nonce = get_nonce(HPN, Handshake_IV),
  
  Header0 = quic_packet:form_header(handshake, Data0, byte_size(Handshake_Payload)),
  
  %% Encrypt the Packet
  {Enc_Frames, Tag} = encrypt(Handshake_Payload, Handshake_Key, Nonce, Header0),
  
  %% Encode the packet number
  Enc_Pkt_Num = encrypt_pkt_num(HPN, Pkt_Num_Secret, Tag),
  
  %% Update Data
  Data = Data0#quic_data{
           hand_pkt_num = HPN + 1,
           hand_ack = Ack,
           crypto = Crypto0#quic_crypto{
                      transcript = Transcript,
                      handshake_offsets = {Send + byte_size(Fin) + 1, _Recv}
                     }
          },
  
  %% Replace the packet number
  Head_Len = byte_size(Header0),
  <<Header:Head_Len/binary, _Rest/binary>> = Header0,
  
  {ok, Data, <<Header/binary, Enc_Pkt_Num/binary, Tag/binary, Enc_Frames/binary>>};

form_packet(finished,
            #quic_data{
               type = client,
               hand_ack = Ack0,
               hand_pkt_num = HPN,
               crypto = #quic_crypto{
                           state = handshake,
                           client_handshake_secret = Client_HS_Secret,
                           client_handshake_key = Handshake_Key,
                           client_handshake_iv = Handshake_IV,
                           pkt_num_handshake_secret = Pkt_Num_Secret,
                           transcript = Transcript0,
                           handshake_offsets = {Send, _Recv}
                          } = Crypto0
              } = Data0) ->
  
  %% Creates the tls client finished packet.

  %% First the finished key has to be derived.
  Fin_Key = derive_secret(finished, Client_HS_Secret, <<>>),

  Fin = encode_tls_fin(Fin_Key, Transcript0),
  
  %% Add it to the transcript
  Transcript = <<Transcript0/binary, Fin/binary>>,
  
  %% Wrap in a crypto frame
  Offset = to_var_length(Send),
  Length = to_var_length(byte_size(Fin)),
  Crypto_Fin = <<16#18:8, Offset/binary, Length/binary, Fin/binary>>,
  
  %% Add acks.
  {Ack_Frames, Ack} = quic_packet:to_ack_frame(Ack0),
  Handshake_Payload = <<Crypto_Fin/binary, Ack_Frames/binary>>,
  
  %% Create the nonce.
  Nonce = get_nonce(HPN, Handshake_IV),
  
  Header0 = quic_packet:form_header(handshake, Data0, byte_size(Handshake_Payload)),
  
  %% Encrypt the Packet
  {Enc_Frames, Tag} = encrypt(Handshake_Payload, Handshake_Key, Nonce, Header0),
  
  %% Encode the packet number
  Enc_Pkt_Num = encrypt_pkt_num(HPN, Pkt_Num_Secret, Tag),
  
  %% Update Data
  Data = Data0#quic_data{
           hand_pkt_num = HPN + 1,
           hand_ack = Ack,
           crypto = Crypto0#quic_crypto{
                      transcript = undefined,
                      %% Transcript is no longer needed.
                      %% This would be used to create the resumption master
                      %% secret for both server and client. Not implemented.
                      handshake_offsets = {Send + byte_size(Fin) + 1, _Recv}
                     }
          },
  
  %% Replace the packet number
  Head_Len = byte_size(Header0),
  <<Header:Head_Len/binary, _Rest/binary>> = Header0,
  
  {ok, Data, <<Header/binary, Enc_Pkt_Num/binary, Tag/binary, Enc_Frames/binary>>}.


-spec form_packet(early_data, Data, Frames) -> {ok, Data, Packet} when
    Data :: #quic_data{},
    Frames :: [quic_frames()],
    Packet :: binary().
%% Forms early 0-RTT data for the client.

form_packet(early_data,
            #quic_data{
               type = client,
               init_ack = Ack0,
               init_pkt_num = IPN,
               crypto = #quic_crypto{
                           pkt_num_init_secret = Pkt_Num_Secret,
                           client_init_iv = IV,
                           client_init_key = Key
                          }
              } = Data0,
            Frames) ->
  %% This sends early 0-RTT data to the server.
  %% The server cannot send 0-RTT data so there is no clause for them.
  
  Nonce = get_nonce(IPN, IV),
  
  {ok, Data, Header, Payload} = 
    quic_packet:form_packet(early_data, Data0, Frames),
  
  %% Encrypt the Packet
  {Enc_Frames, Tag} = encrypt(Payload, Key, Nonce, Header0),
  
  %% Encode the packet number
  Enc_Pkt_Num = encrypt_pkt_num(HPN, Pkt_Num_Secret, Tag),

  Data = Data0#quic_data{
           init_pkt_num = HPN + 1,
           init_ack = Ack
          },
  
  %% Replace the packet number
  Head_Len = byte_size(Header0),
  <<Header:Head_Len/binary, _Rest/binary>> = Header0,
  
  {ok, Data, <<Header/binary, Enc_Pkt_Num/binary, Tag/binary, Enc_Frames/binary>>}.


-spec parse_packet(Raw_Packet, Data) -> Result when
    Raw_Packet :: binary(),
    Data :: #quic_data{},
    Result :: Packet |
              {coalesced, [Packet]} |
              {retry, Data} |
              {vx_neg, Versions} |
              {quic_error, Reason} |
              not_quic | 
              invalid_quic,
    Packet :: {Packet_Type, Data, Frames, #tls_record{}} |
              %% When we know how to decrypt it and when we don't.
              {Packet_Type, Raw_Packet},
    Frames :: [#quic_frame{}],
    Packet_Type :: initial |
                   handshake |
                   protected |
                   short,
    Versions :: [Version],
    Version :: version(),
    Reason :: gen_quic:errors().

parse_packet(<<1:1, 16#1f:7, _Rest/bits>> = Raw_Packet0,
             #quic_data{
                type = server,
                crypto = #quic_crypto{
                            state = undefined
                           } 
               }= Data0) ->
  %% The first initial packet from the client is received.
  case quic_packet:parse_header(Raw_Packet0, Data0) of
    {ok, Data1, Raw_Packet} ->
      %% Valid header info received.
      %% Initialize the server-side crypto
      Data2 = crypto_init(Data1),
      parse_packet(Raw_Packet0, Data2);
    { ->
      

parse_packet(<<1:1, Type:7, _Rest/bits>> = Raw_Packet, 
             #quic_data{
                type = server,
                crypto = #quic_crypto{
                            pkt_num_init_secret = Pkt_Secret1,
                            client_init_key = Key1,
                            client_init_iv = IV1,
                            pkt_num_handshake_secret = Pkt_Secret2,
                            client_handshake_key = Key2,
                            client_handshake_iv = IV2,
                            pkt_num_protected_secret = Pkt_Secret3,
                            client_protected_key = Key3,
                            client_protected_iv = IV3
                           }
               } = Data) ->
  %% Long packet type received.
  %% Definitely could have better variable names.
  %% Check the type of the packet and dispatch to parser with correct crypto stuff.
  case type_to_atom(Type) of
    not_quic ->
      not_quic;

    initial ->
      decrypt_and_parse(Raw_Packet, Data, Key1, IV1, Pkt_Secret1, initial);

    handshake ->
      decrypt_and_parse(Raw_Packet, Data, Key2, IV2, Pkt_Secret2, handshake);

    protected ->
      decrypt_and_parse(Raw_Packet, Data, Key3, IV3, Pkt_Secret3, protected)

    %% Server cannot receive retry or version negotiation packets.
  end;

parse_packet(<<1:1, Type:7, _Rest/bits>> = Raw_Packet, 
             #quic_data{
                type = client,
                crypto = #quic_crypto{
                            pkt_num_init_secret = Pkt_Secret1,
                            server_init_key = Key1,
                            server_init_iv = IV1,
                            pkt_num_handshake_secret = Pkt_Secret2,
                            server_handshake_key = Key2,
                            server_handshake_iv = IV2,
                            pkt_num_protected_secret = Pkt_Secret3,
                            server_protected_key = Key3,
                            server_protected_iv = IV3
                           }
               } = Data) ->
  %% Long packet type received.
  %% Definitely could have better variable names.
  %% Check the type of the packet and dispatch to parser with correct crypto stuff.
  case type_to_atom(Type) of
    not_quic ->
      not_quic;

    initial ->
      decrypt_and_parse(Raw_Packet, Data, Key1, IV1, Pkt_Secret1, initial);

    handshake ->
      decrypt_and_parse(Raw_Packet, Data, Key2, IV2, Pkt_Secret2, handshake);

    protected ->
      decrypt_and_parse(Raw_Packet, Data, Key3, IV3, Pkt_Secret3, protected);

    retry ->
      %% Retry packets are not encrypted.
      quic_packet:parse_packet(Raw_Packet, Data);
    
    vx_neg ->
      %% Version Negotiation Packets are not encrypted.
      quic_packet:parse_packet(Raw_Packet, Data)
  end;


%% TODO: Add check for phase bit to see if keys are still valid.
parse_packet(<<0:1, _Rest/bits>> = Raw_Packet,
             #quic_data{
                type = Type,
                conn = #quic_conn{
                          src_conn_ID = Src_Conn_ID
                          %% Receiver's connection id.
                         },
                crypto = #quic_crypto{
                            state = protected,
                            client_protected_key = Client_Key,
                            client_protected_iv = Client_IV,
                            server_protected_key = Server_Key,
                            server_protected_iv = Server_IV,
                            pkt_num_protected_secret = Pkt_Secret
                           }
               } = Data) ->
  %% Short packet received and Crypto is in protected state.
  {Key, IV} = 
    case Type of
      server ->
        {Client_Key, Client_IV};
      
      client ->
        {Server_Key, Server_IV}
    end,

  Conn_Len = byte_size(Src_Conn_ID),

  {ok, Pkt_Num, Header, Enc_Frames} = 
    decrypt_pkt_num({short, Conn_Len}, Raw_Packet, Pkt_Secret),
  
  Nonce = get_nonce(IV, Pkt_Num),
  
  Packet = decrypt(Enc_Frames, Key, Nonce, Header),
  
  quic_packet:parse_packet(Packet, Data).


%% If the Keys or IV are not defined, return the packet type.
decrypt_and_parse(<<_Packet/binary>>, _Data, undefined, _, _, Type) ->
  Type;

decrypt_and_parse(<<_Packet/binary>>, _Data, _, undefined, _, Type) ->
  Type;

decrypt_and_parse(<<_Packet/binary>>, _Data, _, _, undefined, Type) ->
  Type;

decrypt_and_parse(<<Raw_Packet/binary>>, Data, Key, IV, Pkt_Secret, _Type) ->
  %% This is only called by long header packets.
  {ok, Pkt_Num, Header, Enc_Frames} = decrypt_pkt_num(long, Raw_Packet, Pkt_Secret),
  
  Nonce = get_nonce(IV, Pkt_Num),
  
  Packet = decrypt(Enc_Frames, Key, Nonce, Header),
  
  quic_packet:parse_packet(Packet, Data).
  


-spec initial_extract(Client_ID) -> PRK when
    Client_ID :: binary(),
    PRK :: binary().
%% Equivalent to HKDF-Extract. Using the hkdf library.
%% Section 5.1.1
initial_extract(Client_ID) ->
  extract(Client_ID, ?INIT_SALT).


-spec extract(Secret, Salt) -> Secret when
    Secret :: binary(),
    Salt :: binary().

extract(Secret, Salt) ->
  hkdf:extract(sha256, Secret, Salt).


-spec derive_secret(Label, PRK, Context) -> Secret when
    Label :: client_initial |
             server_initial |
             packet_num |
             client_hs |
             server_hs |
             client_app |
             server_app |
             finished |
             derived, %% There might be more.
    PRK :: binary(),
    Context :: binary(),
    Secret :: binary().
%% Equivalent to HKDF-Expand
%% Maybe move these contexts to Macros.
%% TODO: Add more.
derive_secret(client_initial, PRK, Context) ->
  %% Section 5.1: QUIC-TLS
  expand(PRK, "quic client in", Context);
derive_secret(server_initial, PRK, Context) ->
  %% Section 5.1: QUIC-TLS
  expand(PRK, "quic server in", Context);
derive_secret(packet_num, PRK, Context) ->
  %% Section 5.3: QUIC-TLS
  expand(PRK, "quic pn", Context);
derive_secret(client_hs, PRK, Context) ->
  %% TLS 1.3 client handshake traffic secret.
  expand(PRK, "quic c hs traffic", Context);
derive_secret(server_hs, PRK, Context) ->
  %% TLS 1.3 server handshake traffic secret.
  expand(PRK, "quic s hs traffic", Context);
derive_secret(client_ap, PRK, Context) ->
  %% TLS 1.3 client application traffic secret.
  expand(PRK, "quic c ap traffic", Context);
derive_secret(server_ap, PRK, Context) ->
  %% TLS 1.3 server application traffic secret.
  expand(PRK, "quic s ap traffic", Context);
derive_secret(finished, PRK, Context) ->
  %% TLS 1.3 finished record secret.
  expand(PRK, "quic finished", Context);
derive_secret(derived, PRK, Context) ->
  %% TLS 1.3 derive secret.
  expand(PRK, "quic derived", Context).


-spec expand(keys, PRK) -> Result when
    PRK :: binary(),
    Result :: {binary(), binary()}.
%% Expands the keys and ivs at each encryption level.

expand(keys, PRK) ->
  {expand(PRK, "quic key", <<>>),
   expand(PRK, "quic iv", <<>>)}.


-spec expand(PRK, Label, Context) -> Secret when
    PRK :: binary(),
    Label :: iodata(),
    Context :: binary(),
    Secret :: binary().
%% Only using 32 byte hash length with sha256.
%% Also with the hkdf library.
expand(PRK, Label, Context) when is_list(Label) ->
  C_Hash = crypto:hash(sha256, Context),
  expand(PRK, <<Label/binary>>, C_Hash);

expand(PRK, Label, Context) ->
  Label_Len = byte_size(Label),
  Context_Len = byte_size(Context),
  Info = <<32:16, Label_Len:8, Label/binary, Context_Len:8, Context/binary>>,
  hkdf:expand(sha256, PRK, Info, 32).


-spec get_nonce(Pkt_Num, PRK) -> Nonce when
    Pkt_Num :: non_neg_integer(),
    PRK :: binary(),
    Nonce :: binary().
%% Section 5.2 of QUIC-TLS
%% "The nonce, N, is formed by combining the packet
%% protection IV with the packet number.  The 64 bits of the
%% reconstructed QUIC packet number in network byte order are left-
%% padded with zeros to the size of the IV.  The exclusive OR of the
%% padded packet number and the IV forms the AEAD nonce."
%% This is equivalent to incrementing the nonce by the packet number.
get_nonce(Pkt_Num, PRK) ->
  %% Take the last 4 bytes of the PRK to XOR with the Pkt_Num.
  <<P1:28/unit:8, P2:4/unit:8>> = PRK,
  %% PRK should be exactly 32 bytes long.
  %% This might make more sense as a guard instead of an assert failure.
  %% Or just move to function clause.
  <<P1/binary, (bitxor(<<Pkt_Num:4/unit:8>>, P2))/binary>>.


-spec encrypt(Packet, PRK, Nonce, Header) -> {Encrypted, Tag} when
    Packet :: binary(),
    PRK :: binary(),
    Nonce :: binary(),
    Header :: binary(),
    Encrypted :: binary(),
    Tag :: binary().
%% Section 5.2
%% "The associated data, AAD, for the AEAD is the contents of the QUIC
%% header, starting from the flags octet in either the short or long
%% header."
%% The header includes the unencrypted packet number. For long headers, it also
%% includes the payload length, connection ids (destination and 
%% source), Version number, and connection id lengths. For short
%% headers, the destination connection id is included.
%%
%% "The input plaintext, Packet, for the AEAD is the content of the 
%% QUIC frame following the header"
%% 
%% "The output ciphertext, <<Tag/binary, Encrypted/binary>>, of the
%% AEAD is transmitted in place of Packet."
%%
%% Maybe change output to be the <<Tag/binary, Encrypted/binary>>
%% binary as that is how it will be used. Tag will be 16 bytes.
encrypt(Packet, PRK, Nonce, Header) ->
  crypto:block_encrypt(aes_gcm, PRK, Nonce, {Header, Packet}).


-spec decrypt(Encrypted, PRK, Nonce, Header) -> Packet when
    Encrypted :: binary(),
    PRK :: binary(),
    Nonce :: binary(),
    Header :: binary(),
    Packet :: binary().

decrypt(Encrypted, PRK, Nonce, Header) ->
  crypto:block_decrypt(aes_gcm, PRK, Nonce, {Header, Encrypted, 16}).


-spec encrypt_pkt_num(Pkt_Num, Pkt_Secret, Enc_Tag) -> Pkt_Enc when
    Pkt_Num :: non_neg_integer(),
    Pkt_Secret :: binary(),
    Enc_Tag :: binary(),
    Pkt_Enc :: binary().
%% Section 5.3 of Quic-TLS.
%% The encryption algorithm is AES-CTR and Enc_Tag is the AEAD Tag output.
%% For now, all packet numbers are going to be encoded as 4 bytes long to
%% make the corresponding sampling and decryption easier.
encrypt_pkt_num(Pkt_Num, Secret, Enc_Tag) ->
  State = crypto:stream_init(aes_ctr, Secret, Enc_Tag),
  {_New_State, Cipher} = crypto:stream_encrypt(State, <<Pkt_Num:32>>),
  Cipher.


-spec decrypt_pkt_num(Type, Encrypted, Secret) -> Result when
    Type :: {short, Dest_Conn_Len} |
            long,
    Dest_Conn_Len :: non_neg_integer(),
    Encrypted :: binary(),
    Secret :: binary(),
    Result :: {ok, Pkt_Num, Header, Enc_Frames},
    Pkt_Num :: non_neg_integer(),
    Header :: binary(),
    Enc_Frames :: binary().
%% The short packet header skips one-byte for the packet_type,
%% the length of the destination connection id, and 4 bytes for the
%% packet_number then samples the first 16 bytes.
%% The decryption returns the entire decrypted header with the packet number
%% in order to ease decryption of the remainder of the packet.
decrypt_pkt_num({short, Dest_Conn_Len}, Enc_Pkt, Secret) ->

  <<Type:8, Dest_Conn:Dest_Conn_Len/unit:8, Enc_Pkt_Num:32, 
    Sample:16/unit:8, Enc_Frames/binary>> = Enc_Pkt,

  State = crypto:stream_init(aes_ctr, Secret, <<Sample:16/unit:8>>),
  {_New_State, Pkt_Num} = crypto:stream_decrypt(State, <<Enc_Pkt_Num:32>>),
  {ok, Pkt_Num, 
   <<Type:8, Dest_Conn:Dest_Conn_Len/unit:8, Pkt_Num:32>>, 
   Enc_Frames};

%% The long packet header skips one-byte for the packet_type, four bytes for the
%% version number, one-byte for the dest_conn_len and src_conn_len, the lengths of 
%% the dest_conn and src_conn, the payload length, and 4 bytes for the packet number. 
%% The variable length payload makes this slightly more complicated.
%% Might need to add a separate case for 0 length Dest and Src connection ids;
decrypt_pkt_num(long, <<Type:8, VX:32, Dest_Conn_Len:4, Src_Conn_Len:4,
                        Dest_Conn_ID:Dest_Conn_Len/unit:8,
                        Src_Conn_ID:Src_Conn_Len/unit:8,
                        Payload_Flag:2, Rest/bits>>,
                Secret) ->
  %% Section 7.1 of QUIC Transport.
  Payload_Len =
    case Payload_Flag of
      0 ->
        6;
      1 ->
        14;
      2 ->
        30;
      3 ->
        62
    end,
  
  <<Payload:Payload_Len, Enc_Pkt_Num:32, Tag:16/unit:8, Enc_Frames/binary>> = Rest,
  
  State = crypto:stream_init(aes_ctr, Secret, <<Tag:16/unit:8>>),
  {_New_State, Pkt_Num} = crypto:stream_decrypt(State, <<Enc_Pkt_Num:32>>),

  Header = <<Type:8, VX:32, Dest_Conn_Len:4, Src_Conn_Len:4,
             Dest_Conn_ID:Dest_Conn_Len/unit:8,
             Src_Conn_ID:Src_Conn_Len/unit:8,
             Payload_Flag:2, Payload:Payload_Len,
             Pkt_Num:32>>,

  {ok, Pkt_Num, Header, Enc_Frames}.


-spec bitxor(binary(), binary()) -> binary().
%% Unfortunately, the Erlang bxor function only works on integers.
%% Simple function to fix that though.
%% Apparently there is crypto:bxor which might work, but I already wrote this.
bitxor(Bin1, Bin2) when is_binary(Bin1),
                        is_binary(Bin2),
                        byte_size(Bin1) == byte_size(Bin2) ->
  bitxor(Bin1, Bin2, <<>>).

bitxor(<<>>, <<>>, Acc) -> Acc;

%% Appending to binaries is amortized O(1).
bitxor(<<B1:8, Rest1/binary>>,
       <<B2:8, Rest2/binary>>,
       <<Acc/binary>>) ->
  bitxor(Rest1, Rest2, <<Acc/binary, (B1 bxor B2):8>>).


-spec gen_key() -> {Pub_Key, Priv_Key} when
    Pub_Key :: binary(),
    Priv_Key :: binary().
%% Hard-coded for now. Will expand later once working with this one.
gen_key() ->
  crypto:generate_key(ecdh, secp256r1).


-spec gen_key(Priv_Key) -> {Pub_Key, Priv_Key} when
    Priv_Key :: binary(),
    Pub_Key :: binary().
gen_key(Priv_Key) ->
  crypto:generate_key(ecdh, secp256r1, Priv_Key).


-spec shared_secret(Other_Public_Key, Private_Key) -> Secret when
    Other_Public_Key :: binary(),
    Private_Key :: binary(),
    Secret :: binary().
%% Hard-coded for now. Will expand later once working with this one.
shared_secret(Other_Pub_Key, Priv_Key) ->
  crypto:compute_key(ecdh, Other_Pub_Key, Priv_Key, secp256r1).


%%
%%
%%
%%
%% The functions below this point are TLS 1.3 message. They do not encrypt anything,
%% but they return binaries of the messages to encrypt and send.
%% I might change them to be one function that takes consistent parameters
%% instead of the current ones.
%% The returned binaries do not have the QUIC Crypto Frame headers included and
%% those headers are not to be included in the TLS Transcript either (This is not
%% covered in any of the QUIC ietf drafts, but the headers are not included in
%% TLS1.3 and the frame header is similar in function to that header.)
%%
%%
%%
%%

%% The lengths on the client hello, server hello, encrypted extensions need to be
%% double checked, but they should be good.
client_hello(#quic_data{
                type = client,
                version = #quic_version{
                             initial_version = Version
                            },
                crypto = #quic_crypto{
                            pub_key = Pub_Key
                           },
                params = Params
                }) ->
  %% Section 4.1.2 in TLS 1.3
  
  Cipher_Suites = <<16#13:16, 16#1:16>>, %% Section B.4 in TLS 1.3
  %% I'm hard-coding things until I get most everything working.
  %% Other ciphers/params will be supported eventually.
  Cipher_Len = byte_size(Cipher_Suites),

  Hello = <<16#0303:16,
            (crypto:strong_rand_bytes(32)):32/unit:8, %% Random Nonce, Ignored on Server side, but required.
            0:8, %% Legacy_Session_ID_Len set to 0 since not used.
            Cipher_Len:16,
            Cipher_Suites:Cipher_Len/unit:8,
            0:8>>, %% Legacy_Compression_methods. Must be one-byte of 0.
  
  TLS_Ext = encode_tls_extensions(client, Pub_Key),
  TLS_Ext_Len = byte_size(TLS_Ext),
  
  Quic_Ext = encode_extensions(client, Version, Params),
  Quic_Ext_Len = byte_size(Quic_Ext),
  
  Ext_Len = TLS_Ext_Len + Quic_Ext_Len + 2,
  %% 2 for the length of Quic_Ext_Len

  Len = byte_size(Hello) + Ext_Len + 2,
  %% 2 for the length of Ext_Len

  %% The extensions code for in TLS for Quic is 0xffa5.
  %% The client hello message type is 1
  <<1:8, Len:24, Hello/binary, Ext_Len:16, TLS_Ext/binary,
    16#ffa5:16, Quic_Ext_Len:16, Quic_Ext/binary>>.


server_hello(#quic_data{
                type = server,
                crypto = #quic_crypto{
                            pub_key = Pub_Key
                           }
               }) ->
  %% Section 4.1.3 in TLS 1.3
  
  Cipher_Suites = <<16#13:16, 16#1:16>>,
  %% more to come later.
  Cipher_Len = byte_size(Cipher_Suites),

  Hello = <<16#0303:16,
            (crypto:strong_rand_bytes(32)):32/unit:8, %% Random Nonce
            0:8, %% legacy_session_id_echo; hardcoded as 0 in client hello.
            %% TODO: add better support here.
            Cipher_Len:16,
            Cipher_Suites:Cipher_Len/unit:8,
            0:8>>, %% legacy_compression_methods is 0

  TLS_Hello_Ext = encode_tls_extensions(server_hello, Pub_Key),

  TLS_Hello_Len = byte_size(TLS_Hello_Ext),

  H_Len = byte_size(Hello) + TLS_Hello_Len + 2,
  %% 2 is for the length of TLS_Hello_Len

  <<2:8, H_Len:24, Hello/binary, TLS_Hello_Len:16, TLS_Hello_Ext/binary>>.


encrypted_exts(#quic_data{
                  type = server,
                  version = #quic_version{
                               negotiated_version = Neg_Vx,
                               supported_versions = Other_Vx
                              },
                  params = Params
                 }) ->
  TLS_Enc_Ext = encode_tls_extensions(encrypted_ext, none),
  
  Quic_Extensions = encode_extensions(server, [Neg_Vx | Other_Vx], Params),
  Quic_Ext_Len = byte_size(Quic_Extensions),
  
  TLS_Enc_Len = byte_size(TLS_Enc_Ext),
  Enc_Ext_Len = TLS_Enc_Len + Quic_Ext_Len + 2,
  %% The entire encrypted extensions length, 2 for the length of Quic_Ext_Len
  
  %% Quic's TLS parameter extension number is 0xffa5, Section 8.2 of Quic-TLS.
  %% 2 is the server hello message type. 8 is the encrypted extensions type.
  <<8:8, Enc_Ext_Len:24, TLS_Enc_Ext/binary, 16#ffa5:16, Quic_Ext_Len:16, 
    Quic_Extensions/binary>>.


encode_extensions(client, Version,
                  #quic_params{
                     init_max_stream_data = Init_Stream_Data,
                     init_max_data = Init_Max_Data,
                     init_max_bi_streams = Max_Bi_Stream,
                     idle_timeout = Timeout,
                     init_max_uni_streams = Max_Uni_Stream,
                     max_packet_size = Max_Pkt_Size,
                     ack_delay_exp = Ack_Delay_Exp,
                     migration = Mig
                    }) ->
  %% The separation by client/server is due to two components that the server
  %% can utilize, but the client cannot. Not really important now, but will be
  %% in the future when support is expanded.
  %% Those are preferred address and reset token.
  
  Params = <<(encode_param(0, Init_Stream_Data))/binary,
             (encode_param(1, Init_Max_Data))/binary,
             (encode_param(2, Max_Bi_Stream))/binary,
             (encode_param(3, Timeout))/binary,
             (encode_param(5, Max_Pkt_Size))/binary,
             (encode_param(7, Ack_Delay_Exp))/binary,
             (encode_param(8, Max_Uni_Stream))/binary,
             (encode_param(9, Mig))/binary>>,
  
  Param_Len = byte_size(Params),
  
  <<Version:32, Param_Len:16, Params/binary>>;

encode_extensions(server, [Version], Params) ->
  <<Version:32, 0:16, (encode_extensions(server, [], Params))/binary>>;

encode_extensions(server, [Version | Versions], Params) when length(Versions) > 0 ->
  Vx_Len = length(Versions) * 4,
  %% Times for since each Version is 4 bytes (32-bits).
  Vxs = list_to_binary(Versions),
  
  <<Version:32, Vx_Len:16, Vxs/binary, 
    (encode_extensions(server, [], Params))/binary>>;

encode_extensions(server, [], 
                  #quic_params{
                     init_max_stream_data = Init_Stream_Data,
                     init_max_data = Init_Max_Data,
                     init_max_bi_streams = Max_Bi_Stream,
                     idle_timeout = Timeout,
                     preferred_address = Addr,
                     init_max_uni_streams = Max_Uni_Stream,
                     max_packet_size = Max_Pkt_Size,
                     ack_delay_exp = Ack_Delay_Exp,
                     migration = Mig,
                     reset_token = Token
                    }) ->

  Params = <<(encode_param(0, Init_Stream_Data))/binary,
             (encode_param(1, Init_Max_Data))/binary,
             (encode_param(2, Max_Bi_Stream))/binary,
             (encode_param(3, Timeout))/binary,
             (encode_param(4, Addr))/binary,
             (encode_param(5, Max_Pkt_Size))/binary,
             (encode_param(6, Token))/binary,
             (encode_param(7, Ack_Delay_Exp))/binary,
             (encode_param(8, Max_Uni_Stream))/binary,
             (encode_param(9, Mig))/binary>>,
  
  <<(byte_size(Params)):16, Params/binary>>.

%% Not a great or accurate way to filter the params, but it'll do for now.  
%% Accuracy is limited by not checking that required fields are present.
encode_param(_Len, undefined) ->
  <<>>;

encode_param(0, Value) ->
  %% Init Max Stream Data
  %% 32-bit value if present
  Val_Len = byte_size(Value),
  <<0:16, Val_Len:16, Value:32>>;

encode_param(1, Value) ->
  %% Init Max Data
  %% 32-bit value if present
  Val_Len = byte_size(Value),
  <<1:16, Val_Len:16, Value:32>>;

encode_param(2, Value) ->
  %% Init Max Bidirectional Stream Id
  %% 16-bit value if present
  Val_Len = byte_size(Value),
  <<2:16, Val_Len:16, Value:16>>;

encode_param(3, Value) ->
  %% Idle Timeout
  %% 16-bit value if present
  Val_Len = byte_size(Value),
  <<2:16, Val_Len:16, Value:16>>;

encode_param(4, #quic_pref_addr{
                   address = Address,
                   port = Port,
                   conn_id = Conn_ID,
                   reset_token = Token
                  }) ->
  %% Preferred Address
  %% Validation of this should be done when being set.
  %% ie either it is a valid ip, port, id, and token or the entire record is undefined.
  Conn_Len = byte_size(Conn_ID),
  Val_Len = Conn_Len + 1 + 1 + 2 + 16, 
  %% one byte for ip length, one for Conn_Len + IP type, 2 for port, 16 for token
  %% Address can be ipv4 or ipv6
  case Address of

    {I1, I2, I3, I4} ->
      %% IPV4 case.
      Len = Val_Len + 4,
      %% 4 bytes for IPV4
      <<4:16, Len:16, 4:4, 4:8, I1:8, I2:8, I3:8, I4:8,
        Port:16, Conn_Len:4, Conn_ID/binary, Token/binary>>;

    {I1, I2, I3, I4, I5, I6, I7, I8} ->
      %% IPV6 case.
      Len = Val_Len + 16,
      %% 16 bytes for IPV6
      <<4:16, Len:16, 6:4, 16:8,
        I1:16, I2:16, I3:16, I4:16, I5:16, I6:16, I7:16, I8:16,
        Port:16, Conn_Len:4, Conn_ID/binary, Token/binary>>
  end;

encode_param(5, Value) ->
  %% Max Packet Size
  %% 16-bit integer
  Val_Len = byte_size(Value),
  <<5:16, Val_Len:16, Value:16>>;

encode_param(6, Value) ->
  %% Stateless Reset Token
  %% 16 bytes in size
  Val_Len = byte_size(Value),
  <<6:16, Val_Len:16, Value:16/unit:8>>;

encode_param(7, Value) ->
  %% Ack Delay Exponent
  %% 8 bit value
  Val_Len = byte_size(Value),
  <<7:16, Val_Len:16, Value:8>>;

encode_param(8, Value) ->
  %% Init Max Unidirectional Streams
  %% 16 bit value
  Val_Len = byte_size(Value),
  <<8:16, Val_Len:16, Value:16>>;

encode_param(9, true) ->
  %% Migration. It either exists or doesn't exist.
  <<9:16>>;

encode_param(9, _Other) ->
  << >> ;

encode_param(_Len, _Value) ->
  %% Not implemented, but I think this will allow for future version
  %% specific parameters to be implemented somehow.
  %quic_packet:encode_param(Len, Value).
  << >>.


%% Returns the server-side TLS extensions for the server hello and
%% encrypted extension messages.
%% See table in section 4.2 for which parameter goes in which
%% These are hard-coded for now, will be expanded later after everything else is working.
encode_tls_extensions(server_hello, Pub_Key) ->
  %% Included: key_share and supported_versions.
  %% Section 4.2.8 and 4.2.1 respectively of TLS 1.3
  %% key_share corresponds with ecdh, secp256r1
  %% Future support will eventually be added for others.
  %% Not included: pre_shared_key
  Pub_Len = byte_size(Pub_Key),
  <<51:16, (Pub_Len + 4):16, 16#0017:16, Pub_Len:16, Pub_Key:Pub_Len/binary, 
    43:16, 2:16, 16#0304:16>>;

encode_tls_extensions(encrypted_exts, _) ->
  %% Included: server_cert_type (X509), supported_groups
  %% 0x0017 is for group ecdh secp256r1
  %% Not included:  server_name, max_fragment_length,
  %%    app_layer_protocol_negotiation, use_srtp, heartbeat, 
  %%    client_cert_type, early_data
  
  <<20:16, 1:16, 0:8,
    10:16, 2:16, 16#0017:16>>;

%% Returns the client-side TLS extensions for the client hello messages.
%% Corresponds to the above server function, see there for comments.
encode_tls_extensions(client, Pub_Key) ->
  
  Pub_Len = byte_size(Pub_Key),
  
  %% Included: key_share, supported versions, server_cert_type, signature_algs,
  %%           supported_groups
  %% Not Included: server_name, max_fragment_length, status_request,
  %%               signature_algorithms_cert, use_srtp,
  %%               heartbeat, app_layer_prot_negotiation, cert_timestamp,
  %%               client_cert_type, padding (not needed with quic),
  %%               pre_shared_key, psk_key_exchange_modes, cookie (not needed with quic),
  %%               cert_authorities, post_handshake_auth.

  <<51:16, (Pub_Len + 4):16, 16#0017:16, Pub_Len:16, Pub_Key:Pub_Len/binary,
    43:16, 2:16, 16#0304:16, 
    20:16, 1:16, 0:8, 
    %% 0x0403 is the ecdsa_secp256r1_sha256 signature algorithm
    13:16, 2:16, 16#0403:16,
    %% Supported groups is just ecdh secp256r1 which is 0x0017
    10:16, 2:16, 16#0017:16>>.

%% This encodes the certificate(s) in TLS format
%% Section 4.4.2 of TLS13
%% This will need updating when support for RawPublicKey certificates is added.
%% Cert_Chain is in reverse order of what we need.
encode_tls_cert(server, Cert_Chain0, Peer_Cert) when is_list(Cert_Chain0) ->
  %% Handles a chain of certificates
  %% Must all be an x509 certificate, at the moment

  Cert_Chain = lists:reverse(Cert_Chain0),

  {Chain_Bin, Chain_Len} =
    lists:foldl(fun(Cert, {Bin, Len}) -> 
                    Cert_Len = byte_size(Cert) + 1,
                    {<<Bin/binary, 0:8, Cert_Len:24, Cert/binary>>, Len + Cert_Len + 1}
                end,
                {<<>>, 0}, [Peer_Cert | Cert_Chain]),


  Len = Chain_Len + 3 + 1,
  %% 3 bytes for the list length, 1 for the cert_request_context
  %% 11 is the byte message number for certificate
  %% 0 byte for cert_request_context
  <<11:8, Len:24, 0:8, Chain_Len:24, Chain_Bin/binary>>.

%% %% When there is only one cert in the chain. Unrealistic for production.
%% encode_tls_cert(server, Cert) ->
%%   %% Leading 0 byte for the cert_request_context

%%   Cert_Len = byte_size(Cert),
%%   Cert_List_Len = Cert_Len + 1 + 3 + 2,
%%   %% 1 byte for certificate type, 3 for the certificate length, and 2 for extensions
%%   %% x509 is cert_type 0 byte. 0 for extension list size.
%%   %% Possible extensions (not include): status_request and cert_timestamp.

%%   Len = Cert_List_Len + 3 + 1,
%%   %% 3 bytes for the list length, 1 for the cert_request_context
%%   %% 11 is the byte message number for certificate
%%   <<11:8, Len:24, 0:8, Cert_List_Len:24, 0:8, Cert_Len:24, Cert/binary, 0:16>>.


%% Encodes the fields needed for the TLS certificate verify message.
%% Section 4.4.3
%% Signature Algorithm is ecdsa_secp256r1_sha256 for now.
%% I'm not sure this one is correct.
encode_tls_cert_verify(server, #quic_data{
                                  crypto = #quic_crypto{
                                              transcript = Transcript,
                                              cert_priv_key = Cert_Key
                                             }
                                 }) ->
  %% This is repeated twice.
  Leading = <<16#2020202020202020202020202020202020202020202020202020202020202020:256>>,
  %% I'm not sure if this should say QUIC or TLS 1.3
  %% In keeping with the other label changes, I'm using QUIC.
  Context_String = <<"QUIC, server CertificateVerify">>,
  
  %% Transcript is a binary of all the send TLS handshake messages so far.
  %% Includes: Server Hello, Encrypted Extensions, and Certificate at this point.
  Verify_Hash = crypto:hash(sha256, Transcript),
  
  Verify_Content = <<Leading:256, Leading:256,
                     Context_String/binary, 0:8,
                     Verify_Hash/binary>>,
  
  Verify_Signature = crypto:sign(ecdsa, sha256, Verify_Content, [Cert_Key, secp256r1]),
  Sign_Len = byte_size(Verify_Signature),
  
  Len = 2 + 2 + Sign_Len,
  %% 2 for length of sign_len, 2 for signature code
  %% 0x0403 is the ecdsa_secp256r1_sha256 signature code.
  %% 15 is the cert verify message byte number.
  <<15:8, Len:24, 16#0403:16, Sign_Len:16, Verify_Signature/binary>>.


%% The finished tls record
%% Section 4.4.4
%% Same for both server and client.
encode_tls_fin(Key, Transcript) ->
  %% Transcript includes all of the sent handshake messages up to now.
  %% Client/Server Hello, Encrypted Extensions, Certificate, Cert Verify
  %% Client also includes Server Finished.
  Transcript_Hash = crypto:hash(sha256, Transcript),
  
  Fin_Verify = crypto:hmac(sha256, Key, Transcript_Hash),
  Fin_Len = byte_size(Fin_Verify),

  Len = Fin_Len + 2,
  %% 20 is the finished message byte number.
  <<20:8, Len:24, Fin_Len:16, Fin_Verify:32>>.


%% Section 7.1 of QUIC.
to_var_length(Num) when Num < 63 ->
  <<0:2, Num:6>>;
to_var_length(Num) when Num < 16383 ->
  <<1:2, Num:14>>;
to_var_length(Num) when Num < 1073741823 ->
  <<2:2, Num:30>>;
to_var_length(Num) ->
  <<3:3, Num:62>>.

get_var_length(0) ->
  6;
get_var_length(1) ->
  14;
get_var_length(2) ->
  30;
get_var_length(3) ->
  62;
get_var_length(_) ->
  error.

%% Specific function for parsing Crypto Frames.
%% This function returns a #tls_record of the information in the tls message
%% which is then immediately used to rekey or validate the tls message and
%% update #quic_data{}.
%% Parsing this frame could be better optimized, but it is not a primary concern
%% The crypto frame is only heavily used at connection startup and rarely afterwards.
-spec parse_crypto_frame(Frames) -> Result when
    Frames :: binary(),
    Result :: {#tls_record{}, Frames}.

parse_crypto_frame(<<16#18:16, Offset_Flag:2, Rest/binary>>) ->
  %% 0x18 is the type identifier for the crypto frame.
  Offset_Len = get_var_length(Offset_Flag),
  
  <<Offset:Offset_Len, Len_Flag:2, Rest1/binary>> = Rest,
  
  Length_Len = get_var_length(Len_Flag),
  
  <<Length:Length_Len, Crypto_Data:Length/unit:8, Rest2/binary>> = Rest1,
  
  TLS_Info = parse_crypto_frame(Crypto_Data, #tls_record{offset = Offset,
                                                        length = Length,
                                                        temp_bin = Crypto_Data}),
  {TLS_Info, Rest2}.

parse_crypto_frame(<<1:8, Len:24, Client_Hello:Len/binary>>, TLS_Info) ->
  %% Enforce the length to hold true.
  parse_client_hello(Client_Hello, TLS_Info#tls_record{type = client_hello});

parse_crypto_frame(<<2:8, Len:24, Server_Hello:Len/binary>>, TLS_Info) ->
  
  parse_server_hello(Server_Hello, TLS_Info#tls_record{type = server_hello});

parse_crypto_frame(<<8:8, Len:24, Enc_Ext:Len/binary>>, TLS_Info0) ->
  
  parse_tls_extensions(Enc_Ext, TLS_Info0#tls_record{type = encrypted_exts}, 
                       encrypted_exts);

parse_crypto_frame(<<11:8, Len:24, Certificate:Len/binary>>, TLS_Info) ->
  
  parse_certificate(Certificate, TLS_Info#tls_record{type = certificate});

parse_crypto_frame(<<15:8, Len:24, Cert_Verify:Len/binary>>, TLS_Info) ->

  parse_cert_verify(Cert_Verify, TLS_Info#tls_record{type = cert_verify});

parse_crypto_frame(<<20:8, Len:24, Finished:Len/binary>>, TLS_Info) ->

  parse_finished(Finished, TLS_Info#tls_record{type = finished});

parse_crypto_frame(_, _) ->
  #tls_record{type = invalid}.



parse_client_hello(<<16#0303:16, _Random:32/unit:8, 0:8, Cipher_Len:16,
                     Ciphers0:Cipher_Len/binary, 0:8, Ext_Len:16,
                     Extensions:Ext_Len/binary>>, TLS_Info) when 
    Cipher_Len rem 2 == 0 ->
  
  Ciphers = lists:reverse(
              binary_foldl(fun(Ciph, Acc) -> [cipher_to_atom(Ciph) | Acc] end,
                           [], Ciphers0, 2)),
  
  parse_tls_extensions(Extensions, 
                       TLS_Info#tls_record{
                         legacy_version = 16#0303,
                         cipher_suites = Ciphers
                        },
                       client_hello);
  
parse_client_hello(_, _) ->
  #tls_record{type = invalid}.


parse_server_hello(<<16#0303:16, _Random:32/unit:8, 0:8, Cipher_Len:16,
                     Ciphers0:Cipher_Len/binary, 0:8, Ext_Len:16,
                     Extensions:Ext_Len/binary>>, TLS_Info) when
    Cipher_Len rem 2 == 0 ->

  Ciphers = lists:reverse(
              binary_foldl(fun(Ciph, Acc) -> [cipher_to_atom(Ciph) | Acc] end,
                           [], Ciphers0, 2)),
  
  parse_tls_extensions(Extensions, 
                       TLS_Info#tls_record{
                         legacy_version = 16#0303,
                         cipher_suites = Ciphers
                        }, 
                       server_hello);

parse_server_hello(_, _) ->
  #tls_record{type = invalid}.

%% I don't think Chain_Length is needed here.
parse_certificate(<<0:8, _Chain_Len:24, Rest/binary>>, TLS_Info) ->
  parse_certificate(Rest, TLS_Info, []).

%% This is the base case. Extensions in the certificate record are 0 length.
%% Cert of the server must be first and followed by the validating chain of certs.
%% The public_key:pkix_path_validation function expects it in the opposite order.
parse_certificate(<<0:16>>, TLS_Info, [Root_Cert | Cert_Chain] = Acc) ->
  [Peer_Cert | _Other] = lists:reverse(Acc),
  TLS_Info#tls_record{root_cert = Root_Cert,
                      peer_cert = Peer_Cert,
                      cert_chain = Cert_Chain};

parse_certificate(<<0:8, Cert_Len:24, Cert:Cert_Len/binary, Others/binary>>, 
                  TLS_Info, Acc) ->
  parse_certificate(Others, TLS_Info, [Cert | Acc]).

parse_cert_verify(<<Alg:16, Sign_Len:16, Signature:Sign_Len/binary>>, TLS_Info) ->
  TLS_Info#tls_record{
    signature = Signature,
    signature_algs = [signature_to_atom(Alg)]
   };

parse_cert_verify(_, _) ->
  #tls_record{type = invalid}.


parse_finished(<<Len:16, Fin_Verify:Len/binary>>, TLS_Info) ->
  %% Must be entire message.
  TLS_Info#tls_record{cert_verify = Fin_Verify};

parse_finished(_, _) ->
  #tls_record{type = invalid}.


%% Used for the server_hello since Quic extension is encrypted.
parse_tls_extensions(<<>>, TLS_Info, server_hello) ->
  TLS_Info;

%% Switch to quic extension parser when encountered.
parse_tls_extensions(<<16#ffa5:16, _Rest/binary>> = Quic_Params,
                     TLS_Info, Record_Type) ->
  parse_quic_extensions(Quic_Params, TLS_Info, Record_Type);

parse_tls_extensions(<<Ext_Type:16, Ext_Len:16, Extension:Ext_Len/binary, 
                       Rest/binary>>, TLS_Info0, Record_Type) ->
  %% Record_Type is server_hello, client_hello, or encrypted_extensions
  %% This will be used to ensure the extension is in the correct record.
  Ext_Atom = tls_ext_to_atom(Ext_Type),
  TLS_Info = parse_tls_extension(Ext_Atom, Extension, TLS_Info0, Record_Type),
  parse_tls_extensions(Rest, TLS_Info, Record_Type).


parse_quic_extensions(<<16#ffa5:16, _Len:16, Vx:4/binary, Param_Len:16, 
                        Params:Param_Len/binary, Rest/binary>>,
                      TLS_Info0, client_hello) ->

  TLS_Info = TLS_Info0#tls_record{quic_version = Vx},

  case Rest of
    <<>> ->
      %% TLS Extensions do not need to be in any particular order, but in this case
      %% only the quic params remain.
      parse_quic_extensions(Params, TLS_Info, #quic_params{});

    _ ->
      %% There are other TLS Extensions to parse
      parse_tls_extensions(Rest, parse_quic_extensions(Params, TLS_Info, #quic_params{}),
                           client_hello)
  end;

parse_quic_extensions(<<16#ffa5:16, _Len:16, Vx:4/binary, Other_Vxs:8,
                        Vxs:Other_Vxs/binary, Param_Len:16, Params:Param_Len/binary,
                        Rest/binary>>, TLS_Info0, encrypted_exts) ->

  Versions = lists:reverse(binary_foldl(fun(Version, Acc) -> [Version | Acc] end,
                                        [], Vxs, 4)),

  TLS_Info = TLS_Info0#tls_record{quic_version = Vx,
                                  other_quic_versions = Versions},
  
  case Rest of
    <<>> ->
      %% There are no other TLS Extensions to parse.
      parse_quic_extensions(Params, TLS_Info, #quic_params{});

    _More ->
      %% There are more TLS Extensions to parse.
      parse_tls_extensions(Rest, parse_quic_extensions(Params, TLS_Info, #quic_params{}),
                           encrypted_exts)
  end;

%% Base case. This needs to return the #tls_record
parse_quic_extensions(<<>>, TLS_Info, Quic_Params) ->
  TLS_Info#tls_record{quic_params = Quic_Params};

parse_quic_extensions(<<9:16, Rest/binary>>, TLS_Info, Quic_Params) ->
  %% The disable_migration parameter does not have a length, it either is or is not.
  parse_quic_extensions(Rest, TLS_Info, Quic_Params#quic_params{migration=true});

parse_quic_extensions(<<6:16, Token:16/binary, Rest/binary>>, TLS_Info, Quic_Params) ->
  %% The stateless_reset_token parameter has a fixed length and no length modifier.
  parse_quic_extensions(Rest, TLS_Info, Quic_Params#quic_params{reset_token = Token});

parse_quic_extensions(<<Param_Type:16, Param_Len:16, 
                        Param:Param_Len/binary, Rest/binary>>,
                      TLS_Info, #quic_params{} = Quic_Params) ->
  %% The rest are variable length.
  Type = quic_ext_to_atom(Param_Type),
  
  parse_quic_extensions(Rest, TLS_Info,
                        parse_quic_ext(Type, Param, Quic_Params)).

parse_quic_ext(init_max_stream_data, <<Data:32>>, Quic_Params) ->
  Quic_Params#quic_params{init_max_stream_data = Data};

parse_quic_ext(init_max_data, <<Data:32>>, Quic_Params) ->
  Quic_Params#quic_params{init_max_data = Data};

parse_quic_ext(idle_timeout, <<Time:16>>, Quic_Params) ->
  Quic_Params#quic_params{idle_timeout = Time};

parse_quic_ext(init_max_bi_streams, <<Streams:16>>, Quic_Params) ->
  Quic_Params#quic_params{init_max_bi_streams = Streams};

parse_quic_ext(init_max_uni_streams, <<Streams:16>>, Quic_Params) ->
  Quic_Params#quic_params{init_max_uni_streams = Streams};

parse_quic_ext(max_packet_size, <<Size:16>>, Quic_Params) ->
  Quic_Params#quic_params{max_packet_size = Size};

parse_quic_ext(ack_delay_exp, <<Exp:8>>, Quic_Params) ->
  Quic_Params#quic_params{ack_delay_exp = Exp};

parse_quic_ext(preferred_address, <<IPV:4, _Len:8, Rest/bits>>, Quic_Params) ->
  %% Ignore the length of the ip address.
  case IPV of
    4 ->
      %% IPV4 case
      <<IP1:8, IP2:8, IP3:8, IP4:8, Port:16, Conn_Len:4, Conn_ID:Conn_Len/binary,
        Token:16/binary>> = Rest,
      Address = #quic_pref_addr{address = {IP1, IP2, IP3, IP4},
                                port = Port,
                                conn_id = Conn_ID,
                                reset_token = Token},

      Quic_Params#quic_params{preferred_address = Address};
    
    6 ->
      %% IPV6 case
      <<IP1:16, IP2:16, IP3:16, IP4:16, IP5:16, IP6:16, IP7:16, IP8:16,
        Port:16, Conn_Len:4, Conn_ID:Conn_Len/binary,
        Token:16/binary>> = Rest,
      Address = #quic_pref_addr{address = {IP1, IP2, IP3, IP4, IP5, IP6, IP7, IP8},
                                port = Port,
                                conn_id = Conn_ID,
                                reset_token = Token},
      Quic_Params#quic_params{preferred_address = Address}
  end.


quic_ext_to_atom(Ext_Type) ->
  case Ext_Type of
    0 -> init_max_stream_data;
    1 -> init_max_data;
    3 -> idle_timeout;
    2 -> init_max_bi_streams;
    4 -> preferred_address;
    5 -> max_packet_size;
    6 -> reset_token;
    7 -> ack_delay_exp;
    8 -> init_max_uni_streams;
    9 -> migration;
    _ -> error
  end.

%% Not all of these are supported yet.
tls_ext_to_atom(Ext_Type) ->
  case Ext_Type of
    0  -> server_name;
    5  -> status_request;
    10 -> supported_groups;
    13 -> signature_algs;
    14 -> use_srtp;
    15 -> heartbeat;
    16 -> alpn;
    18 -> cert_timestamp;
    19 -> client_cert_type;
    20 -> server_cert_type;
    42 -> early_data;
    43 -> supported_versions;
    47 -> cert_authorities;
    48 -> oid_filters;
    50 -> signature_algs_cert;
    51 -> key_share;
    _  -> error
  end.


parse_tls_extension(supported_groups, <<Groups0/binary>>, TLS_Info, TLS_Type) when
    TLS_Type =/= server_hello ->
  %% Supported groups is in Client Hello and Encrypted Extensions
  %% Each group is 2 bytes

  Groups = lists:reverse(
             binary_foldl(fun(Group, Acc) -> [group_to_atom(Group) | Acc] end,
                          [], Groups0, 2)),

  TLS_Info#tls_record{supported_groups = Groups};

parse_tls_extension(key_share, <<>>, TLS_Info, client_hello) ->
  TLS_Info;

parse_tls_extension(key_share, <<Group:16, Pub_Len:16, 
                                 Pub_Key:Pub_Len/binary, Rest/binary>>, 
                    #tls_record{key_share = KS} = TLS_Info, client_hello) ->
  %% client_hello is a list of key_shares each with a group and key.
  %% Most likely there are not enough to worry about that this append will matter.
  parse_tls_extension(key_share, Rest, 
                      TLS_Info#tls_record{
                        key_share = KS ++ [{group_to_atom(Group), Pub_Key}]
                       }, client_hello);

parse_tls_extension(key_share, <<Group:16, Pub_Len:16, Pub_Key:Pub_Len/binary>>, 
                    TLS_Info, server_hello) ->
  %% server_hello has a single key_share with a group and key.
  TLS_Info#tls_record{key_share = [{group_to_atom(Group), Pub_Key}]};

parse_tls_extension(supported_versions, Versions0, TLS_Info, client_hello) ->
  %% This has to include at a minimum the tls1.3 version (0x0304)
  %% For Quic this cannot include versions below tls 1.3 either 
  %% (checked in validate_tls).
  Versions = lists:reverse(
               binary_foldl(fun(<<Version:2/unit:8>>, Acc) -> [Version | Acc] end, 
                            [], Versions0, 2)),
  
  TLS_Info#tls_record{tls_supported_versions = Versions};

parse_tls_extension(supported_versions, <<Vx:2/unit:8>>, TLS_Info, server_hello) ->
  %% This can only include exactly one version of tls 
  %% For Quic must be greater or equal to tls 1.3 (checked in a different function)
  TLS_Info#tls_record{tls_supported_versions = [Vx]};

parse_tls_extension(server_cert_type, <<0:8>>, TLS_Info, Record_Type) when 
    Record_Type =/= server_hello ->
  %% Supported by client_hello and encrypted_exts
  %% Raw Public Key is not supported yet. Value for that is <<2:8>>
  TLS_Info#tls_record{server_cert_type = x509};

parse_tls_extension(signature_algs, Algs, TLS_Info, client_hello) ->
  %% Can only arrive in the client_hello or certificate request (not supported) records
  %% Is a list of supported signature algorithms Each are two bytes in size.

  Sign_Algs = lists:reverse(
                binary_foldl(fun(Alg, Acc) -> [signature_to_atom(Alg) | Acc] end,
                             [], Algs, 2)),
  TLS_Info#tls_record{signature_algs = Sign_Algs};

parse_tls_extension(_, _, _, _) ->
  %% Everything else is an error at the moment.
  %% The errors do need to be expanded by their different types.
  #tls_record{type = invalid}.


%% More to come, eventually.
%% {cipher description, AEAD_cipher}
cipher_to_atom(16#1301) ->
  {aes_128_gcm_sha256, aes_gcm}.

%% {group, curve}
group_to_atom(16#0017) ->
  {ecdh, secp256r1}.

%% {algorithm, curve, hash}
signature_to_atom(16#0403) ->
  {ecdsa, secp256r1, sha256}.

%% Eventually more to come for these.
ciphers() ->
  [{aes_128_gcm_sha256, aes_gcm}].

groups() ->
  [{ecdh, secp256r1}].

signature_algs() ->
  [{ecdsa, secp256r1, sha256}].


valid_cipher(Ciphers) ->
  is_valid(Ciphers, ciphers()).

valid_signature(Signs) ->
  is_valid(Signs, signature_algs()).

valid_group(Groups) ->
  is_valid(Groups, groups()).


%% Cycles through a list and finds the first element that is a member of the other list.
%% This is used to find the first matching cipher, signature, and group.
is_valid([], _List) ->
  false;

is_valid([Item | Rest], List) ->
  case lists:member(Item, List) of
    false ->
      is_valid(Rest, List);
    
    true ->
      Item
  end.


%% TODO: Check to see if the client and server quic parameters are valid.
valid_params(#quic_params{}) ->
  true;

valid_params(_) ->
  false.


type_to_atom(127) ->
  initial;
type_to_atom(126) ->
  handshake;
type_to_atom(125) ->
  protected;
type_to_atom(Other) ->
  ?DBG("Invalid type: ~p~n", [Other]),
  not_quic.

%% Folds over a binary, Split bytes at a time and applies a function to the
%% Accumulator and the value of Split bytes. Acts like lists:foldl, but it needs the
%% number of bytes from the binary to use at each iteration.
%% Crashes if the size of the binary rem Split is not 0.
%% May be faster if the binary is just split into a list of values
%% and then folded over using lists:foldl.
binary_foldl(_Fun, Acc, <<>>, _) ->
  Acc;

binary_foldl(Fun, Acc, Binary, Split) ->
  <<X:Split/unit:8, Rest/binary>> = Binary,
  binary_foldl(Fun, Fun(X, Acc), Rest, Split).


