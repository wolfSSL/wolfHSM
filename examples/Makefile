
.PHONY: all posix_tcp_wh_client_tcp posix_tcp_wh_server_tcp posix_shm_wh_client_shm posix_shm_wh_server_shm clean

all: posix_tcp_wh_client_tcp posix_tcp_wh_server_tcp posix_shm_wh_client_shm posix_shm_wh_server_shm

posix_tcp_wh_client_tcp:
	make -C posix/tcp/wh_client_tcp

posix_tcp_wh_server_tcp:
	make -C posix/tcp/wh_server_tcp

posix_shm_wh_client_shm:
	make -C posix/shm/wh_client_shm

posix_shm_wh_server_shm:
	make -C posix/shm/wh_server_shm

clean:
	make -C posix/tcp/wh_client_tcp clean
	make -C posix/tcp/wh_server_tcp clean
	make -C posix/shm/wh_client_shm clean
	make -C posix/shm/wh_server_shm clean

