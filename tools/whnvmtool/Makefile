TARGET = whnvmtool
CC ?= gcc

# wolfHSM source files
WOLFHSM_DIR ?= $(CURDIR)/../../
WOLFHSM_SRC = $(wildcard $(WOLFHSM_DIR)/src/*.c)
WOLFHSM_SRC += $(wildcard $(WOLFHSM_DIR)/port/posix/*.c)

# wolfCrypt source files
WOLFSSL_DIR ?= $(CURDIR)/../../../wolfssl
WOLFCRYPT_SRC = \
	$(WOLFSSL_DIR)/wolfcrypt/src/wc_port.c \
	$(WOLFSSL_DIR)/wolfcrypt/src/memory.c \
	$(WOLFSSL_DIR)/wolfcrypt/src/misc.c \
	$(WOLFSSL_DIR)/wolfcrypt/src/cryptocb.c \
	$(WOLFSSL_DIR)/wolfcrypt/src/random.c \
	$(WOLFSSL_DIR)/wolfcrypt/src/asn.c \
	$(WOLFSSL_DIR)/wolfcrypt/src/coding.c \
	$(WOLFSSL_DIR)/wolfcrypt/src/wolfmath.c \
	$(WOLFSSL_DIR)/wolfcrypt/src/tfm.c \
	$(WOLFSSL_DIR)/wolfcrypt/src/fe_operations.c \
	$(WOLFSSL_DIR)/wolfcrypt/src/rsa.c \
	$(WOLFSSL_DIR)/wolfcrypt/src/curve25519.c \
	$(WOLFSSL_DIR)/wolfcrypt/src/hash.c \
	$(WOLFSSL_DIR)/wolfcrypt/src/sha256.c \
	$(WOLFSSL_DIR)/wolfcrypt/src/aes.c \
	$(WOLFSSL_DIR)/wolfcrypt/src/ecc.c \
	$(WOLFSSL_DIR)/wolfcrypt/src/cmac.c

SRC = \
	$(WOLFHSM_SRC) \
	$(TARGET).c


ifeq ($(SCAN),1)
SCAN_LOG = scan_whnvmtool.log
# Default target
.DEFAULT_GOAL := scan
endif

INCLUDE_DIRS = \
	-I$(WOLFHSM_DIR) \
	-I$(WOLFSSL_DIR) \
	-I.

LIBS = \
	-lm \
	-lpthread

LIB_DIRS =

CFLAGS = -Wall $(INCLUDE_DIRS)
CFLAGS += -DWOLFHSM_CFG_ENABLE_SERVER -DWOLFHSM_CFG_NO_SYS_TIME
CFLAGS += -std=c90 -D_GNU_SOURCE -Wno-cpp

# When linking against an installed wolfSSL (WOLFSSL_LIB=1), skip
# WOLFSSL_USER_SETTINGS so the installed library's compiled-in options.h
# is used instead.
ifneq ($(WOLFSSL_LIB),1)
CFLAGS += -DWOLFSSL_USER_SETTINGS
endif

ifneq ($(NOCRYPTO),1)
ifeq ($(WOLFSSL_LIB),1)
# Link against an installed wolfSSL library instead of compiling sources.
# Set WOLFSSL_LIBDIR for a non-default install path. NO_INLINE keeps the
# installed wolfSSL headers C90-clean.
LIBS += -lwolfssl
CFLAGS += -DNO_INLINE
ifneq ($(WOLFSSL_LIBDIR),)
LIB_DIRS += -L$(WOLFSSL_LIBDIR)
endif
else
SRC += \
	$(WOLFCRYPT_SRC)
endif
else
CFLAGS += -DWOLFHSM_CFG_NO_CRYPTO
endif

CFLAGS_EXTRA =  # Additional CFLAGS from the command line
LDFLAGS = $(LIB_DIRS) $(LIBS)
OUT = $(TARGET) # Output executable name

# DEBUG flag
ifeq ($(DEBUG), 1)
	CFLAGS += -g -O0 -DDEBUG -ggdb3 -DWOLFHSM_CFG_DEBUG
else
	CFLAGS += -O2
endif

# Check if DEBUG_VERBOSE is set to 1 and enable verbose WOLFHSM debug output
# Note: DEBUG_VERBOSE implies DEBUG
ifeq ($(DEBUG_VERBOSE),1)
	CFLAGS += -g -O0 -DDEBUG -ggdb3 -DWOLFHSM_CFG_DEBUG -DWOLFHSM_CFG_DEBUG_VERBOSE
endif

ifeq ($(ASAN), 1)
	CFLAGS_EXTRA += -fsanitize=address
endif

# Targets
all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) $(CFLAGS_EXTRA) $(SRC) -o $(OUT) $(LDFLAGS)

# Generate the test NVM image
test-gen: $(OUT)
	rm -f whNvmImage.bin whNvmImage.hex
	./$(OUT) --test test/nvminit/test.nvminit --invert-erased-byte

# Run the negative tests, where invalid configs and key files must fail the tool.
# Order-only prereq on test-gen: every whnvmtool instance binds the same TCP
# port, so the two tool-running targets must not overlap under make -j.
test-invalid: $(OUT) | test-gen
	./test/test_invalid_input.sh ./$(OUT)

# Run the test suite, which requires first generating the test NVM image
check: test
test: $(OUT) test-gen test-invalid
	$(MAKE) -C test/ CFLAGS_EXTRA="-DFLASH_ERASED_BYTE=0x00 $(CFLAGS_EXTRA)" WOLFSSL_DIR=$$(realpath $(WOLFSSL_DIR))
	cd test && ./test_whnvmtool

analyze: $(SRC)
	@set -e; \
	for f in $(SRC); do \
		base=$(basename $$f .c); \
		obj=$$base.o; \
		echo "Analyzing $$f..."; \
		$(CC) $(CFLAGS) -c $$f -o $$obj;\
	done

scan:
	@echo "Running scan-build static analysis"
	@mkdir -p $(WOLFHSM_DIR)/scan_out/
	@scan-build --exclude $(WOLFSSL_DIR)/wolfcrypt \
	            --exclude $(WOLFSSL_DIR)/src \
	            --status-bugs $(MAKE) analyze 2> $(WOLFHSM_DIR)/scan_out/$(SCAN_LOG)

clean: clean-test
	rm -f whNvmImage.bin whNvmImage.hex
	rm -f $(OUT)

clean-test:
	$(MAKE) -C test clean

# PHONY targets
.PHONY: all clean test-gen test-invalid test
