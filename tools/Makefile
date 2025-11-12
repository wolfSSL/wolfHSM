
.PHONY: all testcertgen whnvmtool clean

all: whnvmtool

testcertgen:
	make -C testcertgen $(if $(DEBUG),DEBUG=$(DEBUG)) $(if $(DEBUG_VERBOSE),DEBUG_VERBOSE=$(DEBUG_VERBOSE))

whnvmtool:
	make -C whnvmtool $(if $(DEBUG),DEBUG=$(DEBUG)) $(if $(DEBUG_VERBOSE),DEBUG_VERBOSE=$(DEBUG_VERBOSE))

clean:
	make -C testcertgen clean $(if $(DEBUG),DEBUG=$(DEBUG)) $(if $(DEBUG_VERBOSE),DEBUG_VERBOSE=$(DEBUG_VERBOSE))
	make -C whnvmtool clean $(if $(DEBUG),DEBUG=$(DEBUG)) $(if $(DEBUG_VERBOSE),DEBUG_VERBOSE=$(DEBUG_VERBOSE))
