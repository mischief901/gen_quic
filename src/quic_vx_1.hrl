%% The quic_vx_1 header file defines the version 1 values for types,
%% connection ID lengths, and others.

%% The parsing module and the encoding module.
-define(PARSER, quic_parser_vx_1).
-define(ENCODER, quic_encoder_vx_1).

%% The version number to be included in the header. (32 bits)
-define(VERSION_NUMBER, 1).

%% In bytes, only used when length is not given. 
%% Must be between 4 and 18 bytes inclusive (32 to 144 bits) or 0.
%% Must be at least 8 for initial packet (Section 4.4.1)
-define(DEFAULT_CONN_ID_LENGTH, 8).

%% The type of header for the packet. 
-define(LONG, 1).
-define(SHORT, 0).

-define(DEFAULT_SHORT, 01100).

%% The values associated with specific long header types. (7 bits)
%% -define(TYPE_NAME, #######).
%% Given as an integer that is representable in 7 bits. (=< 127).
-define(INITIAL, 127).
-define(RETRY, 126).
-define(HANDSHAKE, 125).
-define(PROTECTED, 124).
-define(VERSION_NEG, 0).

%% The values associated with specific short header types. (2 bits)
%% -define(TYPE_NAME, #######).
%% Given as an integer that is representable in 2 bits. (0 - 3).
-define(ONEBYTE, 0).
-define(TWOBYTE, 1).
-define(FOURBYTE, 2).

%% The Frame Types (5 bits):
%% -define(FRAME_TYPE, #####).
%% Given as an integer that is representable in 5 bits. (0 - 23).
%% 16 -23 are used to indicate presence of optional fields in stream frames.

-define(PADDING, 0).
-define(RST_STREAM, 1).
-define(CONN_CLOSE, 2).
-define(APP_CLOSE, 3).
-define(MAX_DATA, 4).
-define(MAX_STREAM_DATA, 5).
-define(MAX_STREAM_ID, 6).
-define(PING, 7).
-define(BLOCKED, 8).
-define(STREAM_BLOCKED, 9).
-define(STREAM_ID_BLOCKED, 10).
-define(NEW_CONN_ID, 11).
-define(STOP_SENDING, 12).
-define(ACK_FRAME, 13).
-define(PATH_CHALLENGE, 14).
-define(PATH_RESPONSE, 15).

%% The Connection Error Codes:
%% Given as an integer that is representable in 2 bytes.
%% These are defined by QUIC, Section 11.3

-define(NO_ERROR, 0).
-define(INTERNAL_ERROR, 1).
-define(SERVER_BUSY, 2).
-define(FLOW_CONTROL_ERROR, 3).
-define(STREAM_ID_ERROR, 4).
-define(STREAM_STATE_ERROR, 5).
-define(FINAL_OFFSET_ERROR, 6).
-define(FRAME_FORMAT_ERROR, 7).
-define(TRANSPORT_PARAMETER_ERROR, 8).
-define(VERSION_NEGOTIATION_ERROR, 9).
-define(PROTOCOL_VIOLATION, 10).
-define(UNSOLICITED_PATH_RESPONSE, 11).

%% Frame errors are the errors for a specific frame. Numbers are given as 1xx,
%% where xx is the frame type.
%% Frame Error 116 is used for all Stream Frame errors, probably should be
%% 116 to 123 for the different stream frame options.
-define(FRAME_ERROR_PADDING, 100).
-define(FRAME_ERROR_RST_STREAM, 101).
-define(FRAME_ERROR_CONN_CLOSE, 102).
-define(FRAME_ERROR_APP_CLOSE, 103).
-define(FRAME_ERROR_MAX_DATA, 104).
-define(FRAME_ERROR_MAX_STREAM_DATA, 105).
-define(FRAME_ERROR_MAX_STREAM_ID, 106).
-define(FRAME_ERROR_PING, 107).
-define(FRAME_ERROR_BLOCKED, 108).
-define(FRAME_ERROR_STREAM_BLOCKED, 109).
-define(FRAME_ERROR_STREAM_ID_BLOCKED, 110).
-define(FRAME_ERROR_NEW_CONN_ID, 111).
-define(FRAME_ERROR_STOP_SENDING, 112).
-define(FRAME_ERROR_ACK_FRAME, 113).
-define(FRAME_ERROR_PATH_CHALLENGE, 114).
-define(FRAME_ERROR_PATH_RESPONSE, 115).
-define(FRAME_ERROR_STREAM_FRAME, 116).

%% The Application Error Codes:
%% Given as an integer that is representable in 2 bytes.
%% Only defined application error code by QUIC is 0, the rest are custom to 
%% the application using QUIC, Section 11.4

-define(STOPPING, 0).


-record(quic_vx_1, 
        {type, 
         dest_conn_len, 
         src_conn_len, 
         dest_conn,
         src_conn,
         header_mod, 
         frame_mod, 
         version, 
         payload_len, 
         packet_num
        }).
