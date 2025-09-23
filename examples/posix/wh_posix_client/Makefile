## Makefile for wolfHSM Client example using POSIX port

## Project name
# Sets output filenames
BIN = wh_posix_client

## Important directories
# Base directory for additional project files
PROJECT_DIR				?= .
CONFIG_DIR				?= $(PROJECT_DIR)/config
SHARED_CONFIG_DIR       ?= $(PROJECT_DIR)/../
# wolfSSL and wolfHSM directories
WOLFSSL_DIR				?= ../../../../wolfssl
WOLFHSM_DIR				?= ../../../
WOLFHSM_PORT_DIR		?= $(WOLFHSM_DIR)/port/posix
WOLFHSM_DEMO_CLIENT_DIR	?= $(WOLFHSM_DIR)/examples/demo/client

# Output directory for build files
BUILD_DIR				?= $(PROJECT_DIR)/Build

# Includes
INC =   -I$(PROJECT_DIR) \
		-I$(CONFIG_DIR) \
		-I$(SHARED_CONFIG_DIR) \
		-I$(WOLFSSL_DIR) \
		-I$(WOLFHSM_DIR) \
		-I$(WOLFHSM_PORT_DIR) \
		-I$(WOLFHSM_DEMO_CLIENT_DIR)

# POSIX requires C source be defined before any header
DEF += -D_POSIX_C_SOURCE=200809L

# Library configuration defines for user-supplied settings
DEF += -DWOLFSSL_USER_SETTINGS -DWOLFHSM_CFG

# Architecture flags for assembler, C compiler and linker
ARCHFLAGS ?=

# Enable extra C compiler warnings
CFLAGS_EXTRA = -Werror -Wall -Wextra
# Place functions / data into separate sections to allow unused code removal
CFLAGS_EXTRA += -ffunction-sections -fdata-sections

# C standard to use (default to c90 if not specified)
CSTD 		?= -std=c90

ASFLAGS 	?= $(ARCHFLAGS)
CFLAGS 		?= $(ARCHFLAGS) $(CSTD) $(CFLAGS_EXTRA)
LDFLAGS 	?= $(ARCHFLAGS)

# Enable garbage collection.  Inexact handling of dead_strip
OS_NAME := $(shell uname -s | tr A-Z a-z)
ifeq ($(OS_NAME),darwin)
	LDFLAGS += -Wl,-dead_strip
else
	LDFLAGS += -Wl,--gc-sections
endif

# Libc for printf, libm for math (used with DH)
LIBS = -lc -lm

# LD: generate map
#LDFLAGS += -Wl,-map,$(BUILD_DIR)/$(BIN).map
#LDFLAGS += -Wl,-Map=$(BUILD_DIR)/$(BIN).map

## Makefile options

# Set to @ if you want to suppress command echo
CMD_ECHO ?=

# Check if DEBUG is set to 1 and append debug flags
ifeq ($(DEBUG),1)
	DBGFLAGS = -ggdb -g3
	CFLAGS += $(DBGFLAGS)
	LDFLAGS += $(DBGFLAGS)
endif

## Source files
# Assembly source files
SRC_ASM +=

# wolfCrypt source files
SRC_C += $(wildcard $(WOLFSSL_DIR)/wolfcrypt/src/*.c)

# wolfCrypt test/benchmark source files
SRC_C += $(wildcard $(WOLFSSL_DIR)/wolfcrypt/test/*.c)
SRC_C += $(wildcard $(WOLFSSL_DIR)/wolfcrypt/benchmark/*.c)

# wolfSSL source files
SRC_C += $(wildcard $(WOLFSSL_DIR)/src/*.c)

# Set the default device ID for wolfCrypt tests
ifeq ($(DMA),1)
DEF += -DWC_USE_DEVID=0x57444D41 -DWC_NO_DEFAULT_DEVID
CFLAGS += -DWOLFHSM_CFG_DMA
else
DEF += -DWC_USE_DEVID=0x5748534D

endif

#wolfCrypt test/benchmark source files
SRC_C += $(wildcard $(WOLFSSL_DIR)/wolfcrypt/test/*.c)
SRC_C += $(wildcard $(WOLFSSL_DIR)/wolfcrypt/benchmark/*.c)

# wolfHSM source files
SRC_C +=  $(wildcard $(WOLFHSM_DIR)/src/*.c)

# wolfHSM test code
SRC_C += $(wildcard $(WOLFHSM_DIR)/test/wh_test_keywrap.c)

# wolfHSM port/HAL code
SRC_C +=  $(wildcard $(WOLFHSM_PORT_DIR)/*.c)


# Project
SRC_C +=  $(wildcard $(PROJECT_DIR)/*.c)

# Demo client code
SRC_C += $(wildcard $(WOLFHSM_DEMO_CLIENT_DIR)/*.c)


## Automated processing below

FILENAMES_C = $(notdir $(SRC_C))
OBJS_C = $(addprefix $(BUILD_DIR)/, $(FILENAMES_C:.c=.o))
vpath %.c $(dir $(SRC_C))

OBJS_ASM = $(addprefix $(BUILD_DIR)/, $(notdir $(SRC_ASM:.s=.o)))
vpath %.s $(dir $(SRC_ASM))


## Makefile Targets

.PHONY: build_app build_hex build_static clean

build_app: $(BUILD_DIR) $(BUILD_DIR)/$(BIN).elf
	@echo Build complete.

build_hex: $(BUILD_DIR) $(BUILD_DIR)/$(BIN).hex
	@echo ""
	$(CMD_ECHO) $(SIZE) $(BUILD_DIR)/$(BIN).elf

build_static: $(BUILD_DIR) $(BUILD_DIR)/$(BIN).a
	@echo ""
	$(CMD_ECHO) $(SIZE) $(BUILD_DIR)/$(BIN).a

$(BUILD_DIR):
	$(CMD_ECHO) mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/$(BIN).hex: $(BUILD_DIR)/$(BIN).elf
	@echo "Generating HEX binary: $(notdir $@)"
	$(CMD_ECHO) $(OBJCOPY) -O ihex $< $@

$(BUILD_DIR)/%.o: %.s
	@echo "Compiling ASM file: $(notdir $<)"
	$(CMD_ECHO) $(AS) $(ASFLAGS) $(DEF) $(INC) -c -o $@ $<

$(BUILD_DIR)/%.o: %.c
	@echo "Compiling C file: $(notdir $<)"
	$(CMD_ECHO) $(CC) $(CFLAGS) $(DEF) $(INC) -c -o $@ $<

$(BUILD_DIR)/$(BIN).elf: $(OBJS_ASM) $(OBJS_C)
	@echo "Linking ELF binary: $(notdir $@)"
	$(CMD_ECHO) $(CC) $(LDFLAGS) $(SRC_LD) -o $@ $^ $(LIBS)

$(BUILD_DIR)/$(BIN).a: $(OBJS_ASM) $(OBJS_C)
	@echo "Building static library: $(notdir $@)"
	$(CMD_ECHO) $(AR) -r $@ $^

clean:
	@echo "Cleaning build files"
	@rm -f 	\
			$(BUILD_DIR)/*.elf \
			$(BUILD_DIR)/*.hex \
			$(BUILD_DIR)/*.map \
			$(BUILD_DIR)/*.o \
			$(BUILD_DIR)/*.a \
			$(BUILD_DIR)/*.sym \
			$(BUILD_DIR)/*.disasm

