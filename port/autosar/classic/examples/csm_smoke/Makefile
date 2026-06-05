# AUTOSAR Classic Crypto Driver csm_smoke test harness

BIN := csm_smoke

PROJECT_DIR ?= .
PORT_DIR    ?= $(PROJECT_DIR)/../..
COMMON_DIR  ?= $(PORT_DIR)/../common
WOLFHSM_DIR ?= $(PORT_DIR)/../../..
WOLFSSL_DIR ?= $(WOLFHSM_DIR)/../wolfssl

BUILD_DIR ?= $(PROJECT_DIR)/Build

INC := \
    -I$(PROJECT_DIR) \
    -I$(PROJECT_DIR)/fake_bsw \
    -I$(PORT_DIR)/include \
    -I$(COMMON_DIR)/include \
    -I$(COMMON_DIR)/config \
    -I$(WOLFHSM_DIR) \
    -I$(WOLFSSL_DIR)

DEF := -D_POSIX_C_SOURCE=200809L -DWOLFHSM_CFG -DWOLFSSL_USER_SETTINGS \
       -DWC_USE_DEVID=0x5748534D \
       -DCRYPTO_MAX_ASYNC_JOBS=8 -DWH_AUTOSAR_TEST_HOOKS

CSTD     ?= -std=c99
CFLAGS   ?= -O0 -g -Wall -Wextra -Werror -ffunction-sections -fdata-sections $(CSTD)
LDFLAGS  ?= -Wl,--gc-sections
LIBS     := -lc -lm -lpthread
CFLAGS   += -MMD -MP $(EXTRA_CFLAGS)

ifeq ($(ASAN),1)
    CFLAGS  += -fsanitize=address -fno-omit-frame-pointer
    LDFLAGS += -fsanitize=address
endif
ifeq ($(TSAN),1)
    CFLAGS  += -fsanitize=thread -fno-omit-frame-pointer -fPIE -DWOLFSSL_NO_FENCE
    LDFLAGS += -fsanitize=thread -pie
endif

SRC_C := \
    $(wildcard $(PROJECT_DIR)/*.c) \
    $(PORT_DIR)/src/Crypto.c \
    $(PORT_DIR)/src/Crypto_ProcessJob.c \
    $(PORT_DIR)/src/Crypto_KeyMgmt.c \
    $(PORT_DIR)/src/Crypto_Keystore.c \
    $(PORT_DIR)/src/Crypto_KeyGen.c \
    $(PORT_DIR)/src/Crypto_KeyDerive.c \
    $(PORT_DIR)/src/Crypto_KeyExchange.c \
    $(PORT_DIR)/src/Crypto_Random.c \
    $(PORT_DIR)/config/Crypto_PBcfg.c \
    $(COMMON_DIR)/src/wh_autosar_alg_map.c \
    $(wildcard $(WOLFHSM_DIR)/src/*.c) \
    $(wildcard $(WOLFHSM_DIR)/port/posix/*.c) \
    $(wildcard $(WOLFSSL_DIR)/wolfcrypt/src/*.c) \
    $(wildcard $(WOLFSSL_DIR)/src/*.c)

OBJS := $(addprefix $(BUILD_DIR)/, $(notdir $(SRC_C:.c=.o)))
vpath %.c $(dir $(SRC_C))

.PHONY: all clean
all: $(BUILD_DIR)/$(BIN)

$(BUILD_DIR):
	@mkdir -p $@

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(DEF) $(INC) -c -o $@ $<

$(BUILD_DIR)/$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -rf $(BUILD_DIR)

-include $(OBJS:.o=.d)
