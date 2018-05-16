%% This comprises of the define statements needed to build default quic 
%% packet and frame headers.

-define(LONG, <<1:1>>).
-define(SHORT, <<0:0>>).
-define(INIT, <<127:7>>).
-define(
