## Makefile for wolfHSM tests using POSIX port

## Project name
# Sets output filenames
BIN = wh_test

## Important directories
# Base directory for additional project files
PROJECT_DIR			?= .
CONFIG_DIR			?= $(PROJECT_DIR)/config
# wolfSSL and wolfHSM directories
WOLFSSL_DIR			?= ../../wolfssl
WOLFHSM_DIR			?= ../../wolfHSM
WOLFHSM_PORT_DIR	?= $(WOLFHSM_DIR)/port/posix

# Output directory for build files
BUILD_DIR			?= $(PROJECT_DIR)/Build

# Includes
INC =	-I$(PROJECT_DIR) \
		-I$(CONFIG_DIR) \
		-I$(WOLFSSL_DIR) \
		-I$(WOLFHSM_DIR) \
		-I$(WOLFHSM_PORT_DIR)

# POSIX requires C source be defined before any header
DEF += -D_POSIX_C_SOURCE=200809L

# Library configuration defines for user-supplied settings
DEF += -DWOLFSSL_USER_SETTINGS -DWOLFHSM_CFG

# Ensure this build uses POSIX test features
DEF += -DWOLFHSM_CFG_TEST_POSIX

# Architecture flags for assembler, C compiler and linker
ARCHFLAGS ?=

# Enable extra C compiler warnings
CFLAGS_EXTRA = -Werror -Wall -Wextra
# Place functions / data into separate sections to allow unused code removal
CFLAGS_EXTRA += -ffunction-sections -fdata-sections

# C standard to use (default to c90 if not specified)
CSTD 		?= -std=c90

ASFLAGS		?= $(ARCHFLAGS)
CFLAGS		?= $(ARCHFLAGS) $(CSTD) $(CFLAGS_EXTRA)
LDFLAGS		?= $(ARCHFLAGS)

# Enable garbage collection.  Inexact handling of dead_strip
OS_NAME := $(shell uname -s | tr A-Z a-z)
ifeq ($(OS_NAME),darwin)
	LDFLAGS += -Wl,-dead_strip
else
	LDFLAGS += -Wl,--gc-sections
endif

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

# Add address sanitizer option
ifeq ($(ASAN),1)
	CFLAGS += -fsanitize=address
	LDFLAGS += -fsanitize=address
endif

## wolfSSL defines
ifeq ($(DEBUG_WOLFSSL),1)
	DEF += -DDEBUG_WOLFSSL
endif

ifeq ($(DEBUG_CRYPTOCB),1)
	DEF += -DDEBUG_CRYPTOCB
endif

ifeq ($(DEBUG_CRYPTOCB_VERBOSE),1)
	DEF += -DDEBUG_CRYPTOCB -DDEBUG_CRYPTOCB_VERBOSE
endif


## wolfHSM defines
ifeq ($(NOCRYPTO),1)
	DEF += -DWOLFHSM_CFG_NO_CRYPTO
endif

# Support a DMA-capable build
ifeq ($(DMA),1)
	DEF += -DWOLFHSM_CFG_DMA
endif

# Support a SHE-capable build
ifeq ($(SHE),1)
	DEF += -DWOLFHSM_CFG_SHE_EXTENSION
endif

## Project defines
# Option to build wolfcrypt tests
ifeq ($(TESTWOLFCRYPT),1)
	DEF += -DWOLFHSM_CFG_TEST_WOLFCRYPTTEST
endif

ifeq ($(CLIENT_ONLY_TCP),1)
# Build a client-only test driver to connect to a remote server over TCP
    DEF += -DWOLFHSM_CFG_ENABLE_CLIENT
	DEF += -DWOLFHSM_CFG_TEST_CLIENT_ONLY_TCP
	DEF += -DWOLFHSM_CFG_TEST_NO_CUSTOM_SERVERS
else
# Build both and client server
    DEF += -DWOLFHSM_CFG_ENABLE_CLIENT
	DEF += -DWOLFHSM_CFG_ENABLE_SERVER
endif

## Source files
# Assembly source files
SRC_ASM +=

ifneq ($(NOCRYPTO),1)
# wolfCrypt source files
SRC_C +=  $(wildcard $(WOLFSSL_DIR)/wolfcrypt/src/*.c)

# wolfSSL source files
SRC_C +=  $(wildcard $(WOLFSSL_DIR)/src/*.c)

ifeq ($(TESTWOLFCRYPT),1)

    TESTWOLFCRYPT_DEFAULT_DEVID = 0x5748534D

    # If TESTWOLFCRYPT_DMA is defined but DMA is not, error
    ifneq ($(TESTWOLFCRYPT_DMA),)
        ifeq ($(DMA),)
            $(error "TESTWOLFCRYPT_DMA=1 requires DMA=1 to be set")
        endif
    endif

    # TESTWOLFCRYPT_DEVID and TESTWOLFCRYPT_DMA are mutually exclusive
    ifneq ($(TESTWOLFCRYPT_DMA),)
        ifneq ($(TESTWOLFCRYPT_DEVID),)
            $(error "Cannot set both TESTWOLFCRYPT_DEVID and TESTWOLFCRYPT_DMA. Please choose one.")
        endif
        # Set TESTWOLFCRYPT_DEVID to a hardcoded value when TESTWOLFCRYPT_DMA
        TESTWOLFCRYPT_DEVID = 0x57444D41
    endif

    # Set default TESTWOLFCRYPT_DEVID if not defined by the user
    TESTWOLFCRYPT_DEVID ?= $(TESTWOLFCRYPT_DEFAULT_DEVID)

    # Set the defines for WC_USE_DEVID
    DEF += -DWC_USE_DEVID=$(TESTWOLFCRYPT_DEVID)

	# wolfCrypt test source files
    SRC_C += $(wildcard $(WOLFSSL_DIR)/wolfcrypt/test/*.c)
endif

# End of NOCRYPTO
endif


# wolfHSM source files
SRC_C +=  $(wildcard $(WOLFHSM_DIR)/src/*.c)

# wolfHSM port/HAL code
SRC_C +=  $(wildcard $(WOLFHSM_PORT_DIR)/*.c)

# Project
SRC_C +=  $(wildcard $(PROJECT_DIR)/*.c)


## Automated processing below

FILENAMES_C = $(notdir $(SRC_C))
OBJS_C = $(addprefix $(BUILD_DIR)/, $(FILENAMES_C:.c=.o))
vpath %.c $(dir $(SRC_C))

OBJS_ASM = $(addprefix $(BUILD_DIR)/, $(notdir $(SRC_ASM:.s=.o)))
vpath %.s $(dir $(SRC_ASM))


## Makefile Targets

.PHONY: build_app build_hex build_static clean run

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

# Add additional flag here to avoid pragma
$(BUILD_DIR)/wh_test_check_struct_padding.o: CFLAGS+=-Wpadded -DWOLFHSM_CFG_NO_CRYPTO

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

# No prereq's here to stop from rebuilding with different options
run:
ifeq (,$(wildcard $(BUILD_DIR)/$(BIN).elf))
	$(error $(BUILD_DIR)/$(BIN).elf not found.  Try: make)
else
	$(BUILD_DIR)/$(BIN).elf
endif
