%%%-------------------------------------------------------------------
%%% @author alex <alex@alex-Lenovo>
%%% @copyright (C) 2018, alex
%%% @doc
%%% 
%%% @end
%%%-------------------------------------------------------------------
-module(quic_conn).

-export([connect/4]).
-export([listen/2]).
-export([accept/3]).
-export([open/2]).
-export([send/2]).
-export([recv/3]).
-export([controlling_process/2]).
-export([close/1]).
-export([setopts/2]).
-export([getopts/2]).

%% TODO: Move these 3 functions to quic_statem.erl
-export([handle_frame/2]).
-export([send_and_form_packet/2]).
-export([decrypt_and_parse_packet/3]).

-include("quic_headers.hrl").


%%%===================================================================
%%% API
%%%===================================================================

-spec connect(Address, Port, Opts, Timeout) -> Result when
    Address :: inet:ip_address(),
    Port :: inet:port_number(),
    Opts :: [Opt],
    Opt :: gen_quic:option(),
    Timeout :: non_neg_integer() | infinity,
    Result :: {ok, Socket} | {error, Reason},
    Socket :: gen_quic:socket(),
    Reason :: gen_quic:error().

connect(Address, Port, Opts, Timeout) ->
  {ok, Quic_Opts, Udp_Opts} = inet_quic_util:parse_opts(Opts),
  {ok, Socket} = inet_udp:open(0, [{active, false}, binary | Udp_Opts]),

  Crypto = quic_crypto:default_crypto(),
  Data0 = #{type => client,
            vx_module => quic_vx_1,
            version => #{initial_version => <<1:32>>},
            conn => #{socket => Socket,
                      owner => self()
                     },
            pkt_nums => #{initial => {0, 0, 0},
                          handshake => {0, 0, 0},
                          application => {0, 0, 0}},
            crypto => Crypto
           },
  Data1 = quic_cc:timer_init(Data0),
  Data2 = quic_cc:congestion_init(Data1),

  io:format("Starting connection.~n"),
  %% TODO: Move this to a wrapper function in quic_statem.
  {ok, Pid} = gen_statem:start_link(via(Socket), quic_statem,
                                    [Data2, Quic_Opts], []),

  io:format("Starting balancer.~n"),
  %% TODO: Change empty map to balancer_options when available.
  {ok, _} = stream_balancer:start_balancer(Socket, #{}),
  inet_udp:controlling_process(Socket, Pid),
  io:format("Connecting...~n"),
  gen_statem:call(Pid, {connect, Address, Port, Timeout}).


-spec listen(Port, Opts) -> Result when
    Port :: inet:port_number(),
    Opts :: [Opt],
    Opt :: gen_quic:option(),
    Result :: {ok, Socket} | {error, Reason},
    Socket :: gen_quic:socket(),
    Reason :: inet:posix().

listen(Port, Opts) ->
  {ok, _, Udp_Opts} = inet_quic_util:parse_opts(Opts),
  inet_udp:open(Port, [{active, false}, binary | Udp_Opts]).


-spec accept(LSocket, Timeout, Options) -> Result when
    LSocket :: gen_quic:socket(),
    Timeout :: non_neg_integer() | infinity,
    Options :: [Option],
    Option :: gen_quic:option(),
    Result :: {ok, Socket} | {error, Reason},
    Socket :: gen_quic:socket(),
    Reason :: inet:posix() | timeout.

accept(LSocket, Timeout, Opts) ->
  
  {ok, Quic_Opts, Udp_Opts} = inet_quic_util:parse_opts(Opts),

  %% This socket should remain active. 
  %% parse_opts filters out any user-given active options.
  {ok, Socket} = inet_udp:open(0, [{active, true}, binary | Udp_Opts]),
  
  Crypto = quic_crypto:default_crypto(),
  Data0 = #{type => server,
            vx_module => quic_vx_1,
            conn => #{socket => Socket,
                      owner => self()
                     },
            pkt_nums => #{initial => {0, 0, 0},
                          handshake => {0, 0, 0},
                          application => {0, 0, 0}},
            crypto => Crypto
           },
  Data1 = quic_cc:timer_init(Data0),
  Data2 = quic_cc:congestion_init(Data1),

  %% TODO: Move this to a wrapper function in quic_statem.
  {ok, Pid} = gen_statem:start_link(via(Socket), quic_statem,
                                    [Data2, Quic_Opts], []),
  
  %% TODO: change empty map to balancer_options when available.
  {ok, _} = stream_balancer:start_balancer(Socket, #{}),
  
  inet_udp:controlling_process(Socket, Pid),
  
  %% TODO: Also wrap this function in quic_statem.
  gen_statem:call(Pid, {accept, LSocket, Timeout}).


-spec open(Socket, Opts) -> Result when
    Socket :: gen_quic:socket(),
    Opts :: [gen_quic:stream_option()],
    Result :: {ok, Stream} | {error, Reason},
    Stream :: {Socket, Stream_ID},
    Stream_ID :: non_neg_integer(),
    Reason :: gen_quic:error().

open(Socket, Opts) ->
  %% The stream_balancer module determines how to open streams.
  stream_balancer:open_stream(Socket, Opts).


-spec send(Socket, Data) -> ok when
    Socket :: gen_quic:socket() | {gen_quic:socket(), Stream_ID},
    Stream_ID :: non_neg_integer(),
    Data :: binary() | Frame,
    Frame :: {Pack_Type, quic_frame()},
    Pack_Type :: none | low | balanced.

send(Stream, Data) when is_tuple(Stream) ->
  %% For streams.
  quic_stream:send(Stream, Data);

send(Socket, {_Type, _Frame} = Frames) ->
  %% Called by quic_stream after converted into a quic_frame map.
  gen_statem:cast(via(Socket), {send, Frames}).


%% Packet Length is ignored since it is a datagram.
-spec recv(Socket, Length, Timeout) -> Result when
    Socket :: gen_quic:socket() | {Socket, Stream_ID},
    Stream_ID :: non_neg_integer(),
    Length :: non_neg_integer(),
    Timeout :: non_neg_integer() | infinity,
    Result :: {ok, Data} | {error, Reason},
    Data :: list() | binary(),
    Reason :: inet:posix() | timeout.

recv(Stream, _Length, Timeout) when is_tuple(Stream) ->
  %% For streams.
  quic_stream:recv(Stream, Timeout);

recv(Socket, _Length, Timeout) ->
  gen_statem:call(via(Socket), recv, Timeout).


-spec controlling_process(Socket, Pid) -> Result when
    Socket :: gen_quic:socket() | {Socket, Stream_ID},
    Stream_ID :: non_neg_integer(),
    Pid :: pid(),
    Result :: ok | {error, Reason},
    Reason :: closed | not_owner | badarg | inet:posix().

controlling_process(Stream, Pid) when is_tuple(Stream) ->
  quic_stream:controlling_process(Stream, Pid);

controlling_process(Socket, Pid) ->
  gen_statem:call(via(Socket), {controlling_process, Pid}).


-spec close(Socket) -> ok | {error, not_owner} when
    Socket :: gen_quic:socket() | {Socket, Stream_ID},
    Stream_ID :: non_neg_integer().

close({_Socket, _Stream_ID} = Stream) ->
  quic_stream:close(Stream);

close(Socket) ->
  gen_statem:cast(via(Socket), close).


-spec setopts(Socket, Options) -> Result when
    Socket :: gen_quic:socket(),
    Options :: [Option],
    Option :: gen_quic:option() | gen_udp:option(),
    Result :: ok |
              {error, [Errors]},
    Errors :: {invalid_option, gen_quic:option()} |
              {unknown_option, term()} |
              inet:posix().

setopts(Socket, Options) ->
  case inet_quic_util:parse_opts(Options) of
    {ok, Quic_Opts, Udp_Opts} ->
      case inet:setopts(Socket, Udp_Opts) of
        {error, Posix} ->
          {error, [Posix]};
        ok ->
          gen_statem:cast(via(Socket), {setopts, Quic_Opts})
      end;
    {error, Reasons} ->
      {error, Reasons}
  end.


-spec getopts(Socket, Options) -> Result when
    Socket :: gen_quic:socket(),
    Result :: {error, socket_not_found} |
              {ok, Options},
    Options :: [Option],
    Option :: gen_quic:option() | gen_udp:option().

getopts(Socket, Options) ->
  case inet_quic_util:parse_opts(Options) of
    {ok, Quic_Opts, Udp_Opts} ->
      case inet:getopts(Socket, Udp_Opts) of
        {ok, Udp_Vals} ->
          case gen_statem:call(via(Socket), {getopts, Quic_Opts}) of
            {ok, Quic_Vals} ->
              {ok, Udp_Vals ++ Quic_Vals};
            {error, Reason} ->
              {error, Reason}
          end;
        {error, Posix} ->
          {error, Posix}
      end;
    {error, Reasons} ->
      {error, Reasons}
  end.


via(Socket) ->
  {via, quic_registry, Socket}.


%% This function should behave the exact same across both quic_server and quic_client.
-spec handle_frame(Frame, Data) -> {ok, Data} when
    Data  :: quic_data(),
    Frame :: quic_frame().

handle_frame(#{type := stream_data,
               stream_id := Stream_ID
              } = Frame,
             #{conn := #{socket := Socket}
              } = Data) ->
  %% Cast the Stream Frame to the Stream gen_server denoted by {Socket, Stream_ID}.
  gen_server:cast(via({Socket, Stream_ID}), {recv, Frame}),
  {ok, Data};

handle_frame(#{type := stream_open,
               stream_id := Stream_ID
              } = Frame,
             #{conn := #{socket := Socket,
                         owner := Owner
                        }
              } = Data) ->
  ok = stream_balancer:open_stream({Socket, Stream_ID}, Owner, Frame),
  {ok, Data};

handle_frame(#{} = _Frame, #{} = Data) ->
  {ok, Data}.


-spec send_and_form_packet(Pkt_Type, Data) -> {ok, Data} when
    Pkt_Type :: early_data | short | Handshake_Packet,
    Handshake_Packet :: client_hello | server_hello | encrypted_exts |
                        cert_verify | certificate | finished,
    Data :: quic_data().
send_and_form_packet(Pkt_Type, Data) ->
  %% This Check needs to be moved.
  case {maps:get(cc_info, Data, undefined), maps:get(timer_info, Data, undefined)} of
    {undefined, undefined} ->
      %% congestion_control parameters are not initialized yet
      io:format("Initializing cc info.~n"),
      Data1 = quic_cc:congestion_init(Data),
      io:format("Initializing timer info.~n"),
      Data2 = quic_cc:timer_init(Data1),
      form_ack_frame(Pkt_Type, Data2);
    {_, undefined} ->
      io:format("Initializing timer info.~n"),
      Data1 = quic_cc:timer_init(Data),
      form_ack_frame(Pkt_Type, Data1);
    {undefined, _} ->
      io:format("Initializing cc info.~n"),
      Data1 = quic_cc:congestion_init(Data),
      form_ack_frame(Pkt_Type, Data1);
    _ ->
      form_ack_frame(Pkt_Type, Data)
  end.

%% send_and_form_packet(Pkt_Type, 
%%                      #{
%%                        timer_info = undefined
%%                       } = Data) ->
%%   %% timer parameters are not initialized yet
%%   io:format("Initializing timer info.~n"),
%%   send_and_form_packet(Pkt_Type, quic_cc:timer_init(Data));

%% send_and_form_packet(Pkt_Type, Data) ->
%%   io:format("Forming Packet: ~p~n", [Pkt_Type]),
%%   form_ack_frame(Pkt_Type, Data).

form_ack_frame(Pkt_Type, #{vx_module := Module} = Data0) when 
    Pkt_Type == short;
    Pkt_Type == early_data ->
  %% Acks must be in the same crypto range as the packet.
  {ok, Data1, Ack_Info} = quic_cc:get_ack(application, Data0),
  {ok, Ack_Frame} = quic_packet:form_frame(Module, Ack_Info),
  form_frames(Pkt_Type, Data1, Ack_Frame);

form_ack_frame(Pkt_Type, #{vx_module := Module} = Data0) when 
    Pkt_Type =:= client_hello;
    Pkt_Type =:= server_hello ->

  {ok, Data1, Ack_Info} = quic_cc:get_ack(initial, Data0),
  {ok, Ack_Frame} = quic_packet:form_frame(Module, Ack_Info),
  form_crypto_frame(Pkt_Type, Data1, Ack_Frame);

form_ack_frame(Pkt_Type, #{vx_module := Module} = Data0) ->
  %% All others are in the handshake range
  {ok, Data1, Ack_Info} = quic_cc:get_ack(handshake, Data0),
  {ok, Ack_Frame} = quic_packet:form_frame(Module, Ack_Info),
  form_crypto_frame(Pkt_Type, Data1, Ack_Frame).

form_frames(Pkt_Type, Data0, #{binary := Ack_Bin} = Ack_Frame) ->
  {ok, Size} = quic_cc:available_packet_size(Data0),
  %% Can potentially send more frames.
  Ack_Size = byte_size(Ack_Bin),
  case quic_staging:destage(Data0, Size - Ack_Size) of
    {ok, _, []} when Ack_Size =:= 0 ->
      %% Nothing to send at this point so return.
      {ok, Data0};
    
    {ok, _, []} ->
      %% Nothing small enough to add, but there is an ack_frame.
      form_packet(Pkt_Type, Data0, [Ack_Frame]);
    
    {ok, Data1, Frames} ->
      form_packet(Pkt_Type, Data1, [Ack_Frame | Frames])
  end.


form_crypto_frame(Pkt_Type, #{vx_module := Module} = Data0, Ack_Frame) ->
  %% Create the crypto frame binary, wrap it in the crypto frame header, and add it to the
  %% crypto transcript. This could be prettier, but I want the separation of the steps.
  {ok, Crypto_Data} = quic_crypto:form_frame(Pkt_Type, Data0),
  io:format("Crypto Data: ~p~n", [Crypto_Data]),
  %% Add the transcript before the quic frame headers are added.
  {ok, Data1} = quic_crypto:add_transcript(Crypto_Data, Data0),
  {ok, Crypto_Frame} = quic_packet:form_frame(Module, Crypto_Data),
  io:format("Crypto Frame: ~p~n", [Crypto_Frame]),
  form_packet(Pkt_Type, Data1, [Ack_Frame, Crypto_Frame]).

-spec form_packet(Pkt_Type, Data, Frames) -> Result when
    Pkt_Type :: early_data | short | server_hello | client_hello |
                encrypted_exts | certificate | cert_verify |
                finished,
    Data :: quic_data(),
    Frames :: [Frame],
    Frame :: quic_frame(),
    Result :: {ok, Data}.

form_packet(short, Data0, Frames) ->
  {ok, Data1, Header, Payload, Pkt_Num} = quic_packet:form_packet(short, Data0, Frames),
  encrypt_packet(short, Data1, Frames, Header, Payload, Pkt_Num);

form_packet(early_data, Data0, Frames) ->
  {ok, Data1, Header, Payload, Pkt_Num} = quic_packet:form_packet(early_data, Data0, Frames),
  encrypt_packet(early_data, Data1, Frames, Header, Payload, Pkt_Num);

form_packet(Pkt_Type, Data0, Frames) ->
  Header_Type = case Pkt_Type of
                  Init when Init == server_hello;
                            Init == client_hello ->
                    initial;
                  _ ->
                    handshake
                end,
  
  {ok, Data1, Header, Payload, Pkt_Num} = 
    quic_packet:form_packet(Header_Type, Data0, Frames),
  encrypt_packet(Header_Type, Data1, Frames, Header, Payload, Pkt_Num).


encrypt_packet(Crypto_Range, Data0, Frames, Header, Payload, {Pkt_Num_Int, _Bin} = Pkt_Num) ->
  {ok, Data1, Packet} = quic_crypto:encrypt_packet(Crypto_Range, Data0, 
                                                   Header, Payload, Pkt_Num),
  send_packet(Crypto_Range, Data1, Frames, Packet, Pkt_Num_Int).


send_packet(Crypto_Range, #{conn := #{socket := Socket,
                                      address := IP,
                                      port := Port}
                           } = Data,
            Frames, Packet, Pkt_Num) ->
  prim_inet:sendto(Socket, IP, Port, Packet),
  packet_sent(Crypto_Range, Data, Frames, byte_size(Packet), Pkt_Num).

packet_sent(Range, Data, Frames, Packet_Size, Pkt_Num) ->
  %% Range is needed at this point for resending purposes.
  Pkt_Range = case Range of
                early_data -> application;
                short -> application;
                _ -> Range
              end,

  quic_cc:packet_sent(Pkt_Range, Data, Frames, Packet_Size, Pkt_Num).


-spec decrypt_and_parse_packet(Data, Raw_Packet, Attempt) -> Result when
    Raw_Packet :: binary(),
    Data :: quic_data(),
    Attempt :: non_neg_integer(),
    Result :: {ok, Data} |
              {retry, Data} |
              {error, Reason},
    Reason :: gen_quic:error().

decrypt_and_parse_packet(Data0, Raw_Packet, Attempt) ->
  case quic_packet:parse_header(Raw_Packet, Data0) of
    {ok, Data1, {initial, _Token, _Payload_Length, _Header_Length} = Header_Info} ->
      handle_initial(Data1, Header_Info, Raw_Packet, Attempt);

    {ok, Data1, {vx_neg, Versions}} ->
      gen_statem:cast(self(), {vx_neg, Versions}),
      {ok, Data1};

    {ok, Data1, {retry, Reason}} ->
      handle_retry(Data1, Reason);

    {ok, Data1, Header_Info} ->
      decrypt_packet(Data1, Header_Info, Raw_Packet, Attempt);

    {ok, Data1} ->
      %% This is returned when a packet is not valid for the connection, e.g. it is
      %% not a quic packet, an invalid retry packet, the connection id's do not match.
      {ok, Data1};

    {error, Reason} ->
      io:format(standard_error, "\tError parsing header: ~p~n", [Reason]),
      {error, Reason}
  end.

%% TODO: Maybe push this up to the application layer.
validate_token(Token) ->
  io:format("Token received: ~p~n", [Token]),
  ok.

handle_payload(Data0, Pkt_Type, Pkt_Num, Payload) ->
  {ok, Data1} = quic_cc:queue_ack(Data0, Pkt_Type, Pkt_Num),
  case parse_packet(Data1, Payload) of
    {ok, Frames, Ack_Frames, Crypto_Frames} ->
      io:format("Crypto_Frames: ~p~n", [Crypto_Frames]),
      %% If there are crypto frames they should be handled first.
      Pid = self(),
      lists:map(fun(Crypto_Frame) -> 
                    gen_statem:cast(Pid, {handle_crypto, Pkt_Type, Crypto_Frame}) end,
                Crypto_Frames),
      %% Ack frames should be handled second to speed the recovery process.
      gen_statem:cast(Pid, {handle_acks, Pkt_Type, Ack_Frames}),
      %% All other frames third.
      gen_statem:cast(Pid, {handle, Pkt_Type, Frames}),
      {ok, Data1};

    Other ->
      io:format(standard_error, "\tError parsing frames: ~p~n", [Other]),
      {ok, Data1}
  end.

-spec handle_initial(Data, Header_Info, Raw_Packet, Attempt) -> Result when
    Data :: quic_data(),
    Header_Info :: {initial, Token, Payload_Length, Header_Length},
    Token :: binary(),
    Payload_Length :: non_neg_integer(),
    Header_Length :: non_neg_integer(),
    Raw_Packet :: binary(),
    Attempt :: non_neg_integer(),
    Result :: {ok, Data}.

handle_initial(Data0, {initial, Token, Payload_Length, Header_Length},
               Raw_Packet, Attempt) when byte_size(Token) > 0 ->
  %% Need to check the validity of the token.
  case validate_token(Token) of
    ok ->
      %% The crypto keys and ivs might need to be initialized for the received DCID and SCID.
      %% Does not make changes if already initialized.
      {ok, Data1} = quic_crypto:crypto_init(Data0),
      decrypt_packet(Data1, {initial, Payload_Length, Header_Length}, 
                     Raw_Packet, Attempt);

    invalid ->
      %% Will not match because this branch is Not implemented yet.
      {error, invalid_token}
  end;

handle_initial(Data, {initial, _Token, Payload_Length, Header_Length}, 
               Raw_Packet, Attempt) ->
  %% If there is no token then just continue parsing and decrypting the packet.
  %% This will change when the token validation function is fleshed out.
  io:format("Received initial packet. Setting up crypto.~n"),
  {ok, Data1} = quic_crypto:crypto_init(Data),
  {ok, Data2} = quic_crypto:rekey(Data1),
  decrypt_packet(Data2, {initial, Payload_Length, Header_Length}, Raw_Packet, Attempt).

-spec decrypt_packet(Data, Header_Info, Raw_Packet, Attempt) -> Result when
    Data :: quic_data(),
    Header_Info :: {Type, Payload_Length, Header_Length},
    Type :: initial | handshake | short | early_data,
    Payload_Length :: non_neg_integer(),
    Header_Length :: non_neg_integer(),
    Raw_Packet :: binary(),
    Attempt :: non_neg_integer(),
    Result :: {ok, Data}.

decrypt_packet(Data0, {Pkt_Type, Payload_Length, Header_Length},
               Raw_Packet, Attempt) ->
  io:format("Header_Length: ~p~n", [Header_Length]),
  <<Header_Bin:Header_Length/binary, Enc_Payload/binary>> = Raw_Packet,
  case quic_crypto:decrypt_packet(Data0, {Pkt_Type, Payload_Length, Header_Bin},
                                  Enc_Payload) of
    {ok, Data1, Pkt_Num, Payload} ->
      handle_payload(Data1, Pkt_Type, Pkt_Num, Payload);
        
    {ok, Data1, Pkt_Num, Payload, More_Packets} ->
      gen_statem:cast(self(), {handle_encrypted, More_Packets, 0}),
      handle_payload(Data1, Pkt_Type, Pkt_Num, Payload);
    
    {error, edecrypt} when Attempt < 3 ->
      gen_statem:cast(self(), {handle_encrypted, Raw_Packet, Attempt + 1}),
      {ok, Data0};

    {error, edecrypt} ->
      %% Only try and decrypt it 3 times.
      {ok, Data0}
  end.

handle_retry(#{conn := Conn0} = Data0, {new_dcid, DCID, Retry_Token}) ->
  %% This function should update data with the information that is needed given by the
  %% reason. Most likely it is a different DCID, but other fields will have to be 
  %% considered in the future.
  Data = Data0#{conn := Conn0#{dest_conn_ID := DCID},
                crypto => #{},
                retry_token => Retry_Token},
  {retry, Data}.

parse_packet(Data, Packet) ->
  quic_packet:parse_frames(Packet, Data).


