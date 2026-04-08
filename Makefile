
.PHONY: all test benchmark tools examples lib clean

export DEBUG
export DEBUG_VERBOSE
export AUTH

all: test benchmark tools examples

test:
	make -C test

benchmark:
	make -C benchmark

tools:
	make -C tools

examples:
	make -C examples

SCAN_DIR = ./scan_out

scan_result_check:
	@err=$$(grep -h -o 'error: .*' ./$(SCAN_DIR)/*.log | wc -l); \
	if [ -z "$$err" ]; then \
		err=0; \
	fi; \
	wrn=$$(grep -h -o '^[0-9]\+ warnings\? generated' ./$(SCAN_DIR)/*.log | grep -o '^[0-9]\+' | awk '{s+=$$1} END {print s}');\
	if [ -z "$$wrn" ]; then \
		wrn=0; \
	fi; \
	if [ $$err -eq 0 -a $$wrn -eq 0 ]; then \
		echo "no errors or warnings found";\
		exit 0; \
	else\
		echo "scan-build detected $$err errors and $$wrn warnings";\
		for f in $(SCAN_DIR)/*.log; do \
			echo "---- $$f ----"; \
			cat $$f; \
			echo ""; \
		done; \
		exit 1; \
	fi;

scan:
	@echo "Running scan-build static analysis"
	@rm -rf $(SCAN_DIR)
	@mkdir -p $(SCAN_DIR)
	@make clean
	-@make -j SCAN=1 -C test scan
	@$(MAKE) scan_result_check

clean:
	make -C test clean
	make -C benchmark clean
	make -C tools clean
	make -C examples clean
	rm -rf $(LIB_BUILD)

# -------------------------------------------------------------------------
# Library targets — build/libwolfhsm.so and build/libwolfhsm.a
#
# wolfHSM's default targets (test/benchmark/tools/examples) do not produce
# a linkable library.  wolfP11 and other consumers that link against wolfHSM
# need the library form; this target provides it.
#
# Required compile flags:
#   WOLFHSM_CFG_ENABLE_CLIENT      — gates wh_Client_* API in wh_client_crypto.c;
#                                    without this, all wh_Client_* functions are
#                                    omitted and link fails with undefined refs
#   WOLFHSM_CFG_NO_SYS_TIME        — suppresses the WOLFHSM_CFG_PORT_GETTIME
#                                    requirement in wh_settings.h; consumers that
#                                    do not use wolfHSM's internal timing should
#                                    set this rather than providing a port function
#   HAVE_ANONYMOUS_INLINE_AGGREGATES=1
#                                  — wolfssl/wolfcrypt/types.h auto-sets this for
#                                    C11+ (__STDC_VERSION__ >= 201101L), but not
#                                    for -std=c99 or -std=c90; wh_settings.h
#                                    asserts the macro is set and errors without it
#
# Usage:
#   make lib                        # uses pkg-config for wolfssl flags
#   make lib WOLFSSL_DIR=~/wolfssl  # fallback if pkg-config is unavailable
#
# Output:
#   build/libwolfhsm.so             — shared library
#   build/libwolfhsm.a              — static archive
# -------------------------------------------------------------------------

WOLFSSL_DIR  ?= $(HOME)/wolfssl
LIB_BUILD     = build
LIB_OBJ_DIR   = $(LIB_BUILD)/lib-obj
LIB_SRCS      = $(wildcard src/*.c)
LIB_OBJS      = $(patsubst src/%.c,$(LIB_OBJ_DIR)/%.o,$(LIB_SRCS))
LIB_SO        = $(LIB_BUILD)/libwolfhsm.so
LIB_A         = $(LIB_BUILD)/libwolfhsm.a

WOLFSSL_CFLAGS := $(shell pkg-config --cflags wolfssl 2>/dev/null || echo -I$(WOLFSSL_DIR))

LIB_CFLAGS    = -Wall -Wextra -Werror -std=c99 -fPIC \
                -I. \
                $(WOLFSSL_CFLAGS) \
                -DWOLFHSM_CFG_ENABLE_CLIENT \
                -DWOLFHSM_CFG_NO_SYS_TIME \
                -DHAVE_ANONYMOUS_INLINE_AGGREGATES=1

lib: $(LIB_OBJ_DIR) $(LIB_SO) $(LIB_A)

$(LIB_OBJ_DIR):
	mkdir -p $(LIB_OBJ_DIR)

$(LIB_OBJ_DIR)/%.o: src/%.c
	$(CC) $(LIB_CFLAGS) -c -o $@ $<

$(LIB_SO): $(LIB_OBJS)
	$(CC) -shared -o $@ $^

$(LIB_A): $(LIB_OBJS)
	$(AR) rcs $@ $^
