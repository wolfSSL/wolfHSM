
.PHONY: all wh_posix_client wh_posix_server clean

all: wh_posix_client wh_posix_server

wh_posix_client:
	make -C posix/wh_posix_client $(if $(DEBUG),DEBUG=$(DEBUG)) $(if $(DEBUG_VERBOSE),DEBUG_VERBOSE=$(DEBUG_VERBOSE))

wh_posix_server:
	make -C posix/wh_posix_server $(if $(DEBUG),DEBUG=$(DEBUG)) $(if $(DEBUG_VERBOSE),DEBUG_VERBOSE=$(DEBUG_VERBOSE))

clean:
	make -C posix/wh_posix_client clean $(if $(DEBUG),DEBUG=$(DEBUG)) $(if $(DEBUG_VERBOSE),DEBUG_VERBOSE=$(DEBUG_VERBOSE))
	make -C posix/wh_posix_server clean $(if $(DEBUG),DEBUG=$(DEBUG)) $(if $(DEBUG_VERBOSE),DEBUG_VERBOSE=$(DEBUG_VERBOSE))

