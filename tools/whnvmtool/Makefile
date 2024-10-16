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
	$(WOLFCRYPT_SRC) \
	$(TARGET).c


INCLUDE_DIRS = \
	-I$(WOLFHSM_DIR) \
	-I$(WOLFSSL_DIR) \
	-I.

LIBS = \
	-lm \
	-lpthread

LIB_DIRS =

CFLAGS = -Wall $(INCLUDE_DIRS)
CFLAGS += -DWOLFSSL_USER_SETTINGS
CFLAGS += -std=c90 -D_GNU_SOURCE -Wno-cpp

CFLAGS_EXTRA =  # Additional CFLAGS from the command line
LDFLAGS = $(LIB_DIRS) $(LIBS)
OUT = $(TARGET) # Output executable name

# DEBUG flag
ifeq ($(DEBUG), 1)
	CFLAGS += -g -O0 -DDEBUG -ggdb3
else
	CFLAGS += -O2
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

# Run the test suite, which requires first generating the test NVM image
check: test
test: $(OUT) test-gen
	$(MAKE) -C test/ CFLAGS_EXTRA="-DFLASH_ERASED_BYTE=0x00 $(CFLAGS_EXTRA)" WOLFSSL_DIR=$$(realpath $(WOLFSSL_DIR))
	cd test && ./test_whnvmtool

clean: clean-test
	rm -f whNvmImage.bin whNvmImage.hex
	rm -f $(OUT)

clean-test:
	$(MAKE) -C test clean

# PHONY targets
.PHONY: all clean test-gen test
