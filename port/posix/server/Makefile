## Makefile for wolfHSM generic server using POSIX port

BIN = server

## Important directories
PROJECT_DIR		?= .
WOLFSSL_DIR		?= ../../../../wolfssl
WOLFHSM_DIR		?= ../../../
PORT_DIR		?= ../
GENERIC_DIR		?= $(WOLFHSM_DIR)/examples/generic

BUILD_DIR		?= $(PROJECT_DIR)/Build

# Includes (project dir first for wolfhsm_cfg.h / user_settings.h)
INC =   -I$(PROJECT_DIR) \
	-I$(WOLFSSL_DIR) \
	-I$(WOLFHSM_DIR) \
	-I$(PORT_DIR)

# POSIX requires C source be defined before any header
DEF += -D_POSIX_C_SOURCE=200809L

# Library configuration defines for user-supplied settings
DEF += -DWOLFSSL_USER_SETTINGS -DWOLFHSM_CFG

ARCHFLAGS ?=
CFLAGS_EXTRA ?= -Wextra -g
CFLAGS ?= $(ARCHFLAGS) -Wno-cpp -std=c99 -Wall -Werror $(CFLAGS_EXTRA)
LDFLAGS ?= $(ARCHFLAGS)

OS_NAME := $(shell uname -s | tr A-Z a-z)
ifeq ($(OS_NAME),darwin)
	LDFLAGS += -Wl,-dead_strip
else
	LDFLAGS += -Wl,--gc-sections
endif

LIBS = -lc -lm
CMD_ECHO ?=

ifeq ($(DEBUG),1)
	DBGFLAGS = -ggdb -g3
	CFLAGS += $(DBGFLAGS)
	LDFLAGS += $(DBGFLAGS)
	DEF += -DWOLFHSM_CFG_DEBUG
endif

ifeq ($(DEBUG_VERBOSE),1)
	DBGFLAGS = -ggdb -g3
	CFLAGS += $(DBGFLAGS)
	LDFLAGS += $(DBGFLAGS)
	DEF += -DWOLFHSM_CFG_DEBUG -DWOLFHSM_CFG_DEBUG_VERBOSE
endif

ifeq ($(ASAN),1)
	CFLAGS += -fsanitize=address
	LDFLAGS += -fsanitize=address
endif

## Source files
SRC_C =

ifneq ($(NOCRYPTO),1)
SRC_C += $(wildcard $(WOLFSSL_DIR)/wolfcrypt/src/*.c)
SRC_C += $(wildcard $(WOLFSSL_DIR)/src/*.c)
else
DEF += -DWOLFHSM_CFG_NO_CRYPTO
endif

# wolfHSM source files
SRC_C += $(wildcard $(WOLFHSM_DIR)/src/*.c)

# POSIX port shared code
SRC_C += $(wildcard $(PORT_DIR)/*.c)

# Port server implementation (wh_Port_* functions)
SRC_C += $(PROJECT_DIR)/wh_posix_server_port.c

# Generic server entry point
SRC_C += $(GENERIC_DIR)/wh_generic_server.c

## Object files in Build directory
OBJS_C = $(addprefix $(BUILD_DIR)/, $(notdir $(SRC_C:.c=.o)))

## Compile rule: find source by trying each source directory
COMPILE = $(CC) $(CFLAGS) $(DEF) $(INC) -c -o $@ $<

# Collect unique source directories
SRC_DIRS = $(sort $(dir $(SRC_C)))

# Generate a pattern rule for each source directory
define COMPILE_RULE
$(BUILD_DIR)/%.o: $(1)%.c | $(BUILD_DIR)
	@echo "Compiling: $$(notdir $$<)"
	$$(CMD_ECHO) $$(COMPILE)
endef

$(foreach dir,$(SRC_DIRS),$(eval $(call COMPILE_RULE,$(dir))))

## Makefile Targets

.PHONY: build_app clean

build_app: | $(BUILD_DIR)
build_app: $(BUILD_DIR)/$(BIN).elf
	@echo Build complete.

$(BUILD_DIR)/$(BIN).elf: $(OBJS_C) | $(BUILD_DIR)
	@echo "Linking: $(notdir $@)"
	$(CMD_ECHO) $(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(BUILD_DIR):
	$(CMD_ECHO) mkdir -p $(BUILD_DIR)

clean:
	@echo "Cleaning build files"
	@rm -rf $(BUILD_DIR)
