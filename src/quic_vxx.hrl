%% The quic_vxx header file defines the relevant default values for types,
%% connection ID lengths, and others.

%% The version number to be included in the header. (32 bits)
-define(VERSION_NUMBER, 1).

%% In bytes, only used when length is not given. 
%% Must be between 4 and 18 bytes inclusive (32 to 144 bits) or 0.
-define(DEFAULT_CONN_ID_LENGTH, 4).

%% The type of header for the packet. 
-define(LONG, 1).
-define(SHORT, 0).

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
