## Makefile for wolfHSM tests using POSIX port

## Project name
# Sets output filenames
BIN = wh_benchmark

## Important directories
# Base directory for additional project files
PROJECT_DIR			?= .
MODULES_DIR			?= $(PROJECT_DIR)/bench_modules
CONFIG_DIR			?= $(PROJECT_DIR)/config
# wolfSSL and wolfHSM directories
WOLFSSL_DIR			?= ../../wolfssl
WOLFHSM_DIR			?= ../
WOLFHSM_PORT_DIR	?= $(WOLFHSM_DIR)/port/posix

# Output directory for build files
BUILD_DIR			?= $(PROJECT_DIR)/Build

# Includes
INC =	-I$(PROJECT_DIR) \
		-I$(CONFIG_DIR) \
		-I$(MODULES_DIR) \
		-I$(WOLFSSL_DIR) \
		-I$(WOLFHSM_DIR) \
		-I$(WOLFHSM_PORT_DIR)

# POSIX requires C source be defined before any header
DEF += -D_POSIX_C_SOURCE=200809L

# Library configuration defines for user-supplied settings.
# When linking against an installed wolfSSL (WOLFSSL_LIB=1), skip
# WOLFSSL_USER_SETTINGS so the installed library's compiled-in options.h
# is used instead.
DEF += -DWOLFHSM_CFG
ifneq ($(WOLFSSL_LIB),1)
DEF += -DWOLFSSL_USER_SETTINGS
endif

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
DEF += -DWOLFHSM_CFG_DEBUG
endif

# Check if DEBUG_VERBOSE is set to 1 and enable verbose WOLFHSM debug output
# Note: DEBUG_VERBOSE implies DEBUG
ifeq ($(DEBUG_VERBOSE),1)
DBGFLAGS = -ggdb -g3
CFLAGS += $(DBGFLAGS)
LDFLAGS += $(DBGFLAGS)
DEF += -DWOLFHSM_CFG_DEBUG -DWOLFHSM_CFG_DEBUG_VERBOSE
endif

ifneq ($(DEBUG),1)
CFLAGS += -O2
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

## wolfHSM defines
ifeq ($(NOCRYPTO),1)
	DEF += -DWOLFHSM_CFG_NO_CRYPTO
endif

ifeq ($(SCAN),1)
	SCAN_LOG = scan_benchmark.log
	# Default target
	.DEFAULT_GOAL := scan
endif

# Support a DMA-capable build
ifeq ($(DMA),1)
	DEF += -DWOLFHSM_CFG_DMA
endif

# DMA with non-coherent client caches (requires DMA=1)
ifeq ($(DMA_ALIGNED_PADDED_OUTPUT),1)
    ifneq ($(DMA),1)
        $(error "DMA_ALIGNED_PADDED_OUTPUT=1 requires DMA=1 to be set")
    endif
	DEF += -DWOLFHSM_CFG_DMA_REQUIRE_ALIGNED_PADDED_OUTPUT
endif

# Support a SHE-capable build
ifeq ($(SHE),1)
	DEF += -DWOLFHSM_CFG_SHE_EXTENSION
endif
## Source files
# Assembly source files
SRC_ASM +=

ifneq ($(NOCRYPTO),1)
ifeq ($(WOLFSSL_LIB),1)
# Link against an installed wolfSSL library instead of compiling sources.
# Set WOLFSSL_LIBDIR for a non-default install path. NO_INLINE keeps the
# installed wolfSSL headers C90-clean.
LIBS += -lwolfssl
DEF += -DNO_INLINE
ifneq ($(WOLFSSL_LIBDIR),)
LDFLAGS += -L$(WOLFSSL_LIBDIR)
endif
else
# wolfCrypt source files
SRC_C +=  $(wildcard $(WOLFSSL_DIR)/wolfcrypt/src/*.c)

# wolfSSL source files
SRC_C +=  $(wildcard $(WOLFSSL_DIR)/src/*.c)
endif

# End of NOCRYPTO
endif


# wolfHSM source files
SRC_C +=  $(wildcard $(WOLFHSM_DIR)/src/*.c)

# wolfHSM port/HAL code
SRC_C +=  $(wildcard $(WOLFHSM_PORT_DIR)/*.c)

# Project
SRC_C +=  $(wildcard $(PROJECT_DIR)/*.c)
SRC_C +=  $(wildcard $(MODULES_DIR)/*.c)

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

analyze: $(OBJS_ASM) $(OBJS_C)

scan:$(BUILD_DIR)
	@echo "Running scan-build static analysis"
	@mkdir -p $(WOLFHSM_DIR)/scan_out/
	@scan-build --exclude $(WOLFSSL_DIR)/wolfcrypt \
	            --exclude $(WOLFSSL_DIR)/src \
	            --status-bugs $(MAKE) analyze 2> $(WOLFHSM_DIR)/scan_out/$(SCAN_LOG)

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

# No prereq's here to stop from rebuilding with different options
run:
ifeq (,$(wildcard $(BUILD_DIR)/$(BIN).elf))
	$(error $(BUILD_DIR)/$(BIN).elf not found.  Try: make)
else
	$(BUILD_DIR)/$(BIN).elf
endif
