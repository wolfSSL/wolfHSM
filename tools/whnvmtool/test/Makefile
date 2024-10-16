TARGET = test_whnvmtool
CC ?= gcc

# wolfHSM source files
WOLFHSM_DIR ?= $(CURDIR)/../../../
WOLFHSM_SRC = $(wildcard $(WOLFHSM_DIR)/src/*.c)
WOLFHSM_SRC += $(wildcard $(WOLFHSM_DIR)/port/posix/*.c)

# wolfCrypt source files
WOLFSSL_DIR ?= $(CURDIR)/../../../../wolfssl
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
	-I..

LIBS = \
	-lm \
	-lpthread

LIB_DIRS =

CFLAGS = -Wall $(INCLUDE_DIRS)
CFLAGS += -DWOLFSSL_USER_SETTINGS
CFLAGS_EXTRA =  # Additional CFLAGS from the command line
LDFLAGS = $(LIB_DIRS) $(LIBS)
OUT = $(TARGET) # Output executable name

# DEBUG flag
ifeq ($(DEBUG), 1)
	CFLAGS += -g -O0 -DDEBUG -ggdb3
else
	CFLAGS += -O2
endif

# Targets
all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) $(CFLAGS_EXTRA) $(SRC) -o $(OUT) $(LDFLAGS)

clean:
	rm -f $(OUT)

# PHONY targets
.PHONY: all clean
