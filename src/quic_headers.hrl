%% This comprises of the define statements needed to build default quic 
%% packet and frame headers.


%% Set this to true to add debug statements places. Comment it out otherwise.
-define(DEBUG, true).

-record(quic_conn,
	{
	 version_mod = quic_vxx,
	 cc_mod = quic_cc,
         recovery_mod = quic_recovery,
         crypto_mod = quic_crypto,
	 socket,
	 dest_conn_ID,
	 src_conn_ID,
	 ip_addr,
	 port,
	 crypto_token,
         data,
         max_data,
         max_stream_id
	}).

-record(quic_packet,
        {
         version,
         long,
         type,
         dest_conn_ID_len,
         dest_conn_ID,
         src_conn_ID_len,
         src_conn_ID,
	 crypto_token,
         packet_no,
         payload_len,
         payload,
         ack_frame
        }).

-record(quic_acks,
        {
         largest_enc,
         largest_ack,
         ack_delay_enc,
         ack_delay_time, %% millisecond delay for ack responses.
         ack_block_enc,
         ack_block_count
        }).


-record(quic_frame,
        {
         frame_type,
         len_enc,
         frame_len,
         error_code
        }).

-record(quic_stream,
        {
         owner, %% The PID that initiated the stream
         stream_type, %% Uni or bi-directional stream and server/client owner
         %% (server | client | both)
         stream_id_enc,
         stream_id,
         offset_len_enc,
         offset,
         stream_data, %% current bytes
         max_stream_data %% max bytes
        }).

-ifdef(DEBUG).
-define(DBG(Format, Args), (io:format((Format), (Args)))).
-else.
-define(DBG(Format, Args), ok).
-endif.

