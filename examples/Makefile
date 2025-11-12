
.PHONY: all wh_posix_client wh_posix_server clean

all: wh_posix_client wh_posix_server

wh_posix_client:
	make -C posix/wh_posix_client

wh_posix_server:
	make -C posix/wh_posix_server

clean:
	make -C posix/wh_posix_client clean
	make -C posix/wh_posix_server clean

