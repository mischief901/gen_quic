%% This comprises of the define statements needed to build default quic 
%% packet and frame headers.

-record(quic_conn,
	{
	 version,
	 socket,
	 destID,
	 srcID,
	 ip_addr,
	 port,
	 crypto_token,
	 cong_control
	}).

	    
-ifdef(DEBUG).
-define(DBG(Format, Args), (io:format((Format), (Args)))).
-else.
-define(DBG(Format, Args), ok).
-endif.
