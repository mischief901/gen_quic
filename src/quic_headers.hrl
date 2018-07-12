%% This comprises of the define statements needed to build default quic 
%% packet and frame headers.

%% Set this to true to add debug statements places. Comment it out otherwise.
-define(DEBUG, true).

-record(quic_conn,
        {type         :: client | server,
         socket       :: inet:socket(),
         address      :: inet:socket_address() |
                         inet6:socket_address(),
         port         :: inet:port_number(),
         owner        :: pid(),
         dest_conn_ID :: non_neg_integer(),
         src_conn_ID  :: non_neg_integer()
        }).

-record(quic_packet,
        {
         version,
         long,
         key_phase, %% Short only, not used
         reserve,      %% Short only, not used
         type,
         dest_conn_ID_len,
         dest_conn_ID,
         src_conn_ID_len,
         src_conn_ID,
         crypto_token,
         pkt_num,
         ack_count = 0,
         ack_frames = [],
         ack_delay,
         payload_len,
         payload = [] %% List of quic_frame or quic_acks or quic_stream
        }).

-record(quic_acks,
        {
         type, % ack | gap
         largest,
         smallest
        }).

-record(quic_frame,
        {
         type,
         data
        }).

-record(quic_stream,
        {
         owner            :: pid(),
         type             :: {uni | bi, client | server}, 
         %% Uni or bi-directional stream.
         %% Client or Server owner.
         stream_id        :: non_neg_integer(),
         offset = 0       :: non_neg_integer(),
         current_data = 0 :: non_neg_integer(),
         max_data         :: non_neg_integer(),
         recv             :: {[binary()], [binary()]} |
                             {active, true} |
                             {active, once} |
                             {active, N :: non_neg_integer()}
        }).


%% Simple debugging.
-ifdef(DEBUG).
-define(DBG(Format, Args), (io:format((Format), (Args)))).
-else.
-define(DBG(Format, Args), ok).
-endif.

