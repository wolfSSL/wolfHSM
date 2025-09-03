
.PHONY: all posix_wh_client_posix posix_wh_server_posix clean

all: posix_wh_client_posix posix_wh_server_posix

posix_wh_client_posix:
	make -C posix/wh_client_posix

posix_wh_server_posix:
	make -C posix/wh_server_posix

clean:
	make -C posix/wh_client_posix clean
	make -C posix/wh_server_posix clean

