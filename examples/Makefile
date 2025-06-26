
.PHONY: all posix_tcp_wh_client_tcp posix_tcp_wh_server_tcp clean

all: posix_tcp_wh_client_tcp posix_tcp_wh_server_tcp

posix_tcp_wh_client_tcp:
	make -C posix/tcp/wh_client_tcp

posix_tcp_wh_server_tcp:
	make -C posix/tcp/wh_server_tcp

clean:
	make -C posix/tcp/wh_client_tcp clean
	make -C posix/tcp/wh_server_tcp clean

