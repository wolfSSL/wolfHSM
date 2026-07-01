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
WOLFHSM_DIR			?= ../
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

# Library configuration defines for user-supplied settings.
# When linking against an installed wolfSSL (WOLFSSL_LIB=1), skip
# WOLFSSL_USER_SETTINGS so the installed library's compiled-in options.h
# is used instead of the in-tree user_settings.h.
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
# Auto-generate header dependency files (.d) alongside object files
CFLAGS_EXTRA += -MMD -MP

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

# Add address sanitizer option
ifeq ($(ASAN),1)
	CFLAGS += -fsanitize=address
	LDFLAGS += -fsanitize=address
endif

# Add code coverage option
ifeq ($(COVERAGE),1)
	CFLAGS += --coverage
	LDFLAGS += --coverage
endif

# Enable threadsafe mode, adding lock protection to shared structures
ifeq ($(THREADSAFE),1)
    DEF += -DWOLFHSM_CFG_THREADSAFE
endif

# Add thread sanitizer option (mutually exclusive with ASAN)
ifeq ($(TSAN),1)
    ifeq ($(ASAN),1)
    	$(error TSAN and ASAN cannot be used together)
    endif
    CFLAGS += -fsanitize=thread -fPIE
    DEF += -DWOLFSSL_NO_FENCE
    ifeq ($(STRESS),1)
	    # Force TSAN annotations on in stress test
        DEF += -DWOLFHSM_CFG_TEST_STRESS_TSAN
    endif
    LDFLAGS += -fsanitize=thread -pie
endif

## wolfSSL defines
ifeq ($(DEBUG_WOLFSSL),1)
	DEF += -DDEBUG_WOLFSSL
endif

## wolfHSM defines
ifeq ($(NOCRYPTO),1)
	DEF += -DWOLFHSM_CFG_NO_CRYPTO
endif

# Enable scan-build
ifeq ($(SCAN),1)
	SCAN_LOG = scan_test.log
	# Default target
	.DEFAULT_GOAL := scan
endif

# Support a DMA-capable build
ifeq ($(DMA),1)
	DEF += -DWOLFHSM_CFG_DMA
endif

# Build LMS/XMSS in verify-only mode (omits private-key, sign, and keygen
# paths). May be combined to exercise the mixed (one verify-only) case.
ifeq ($(LMS_VERIFY_ONLY),1)
	DEF += -DWOLFSSL_LMS_VERIFY_ONLY
endif

ifeq ($(XMSS_VERIFY_ONLY),1)
	DEF += -DWOLFSSL_XMSS_VERIFY_ONLY
endif

# Support a SHE-capable build
ifeq ($(SHE),1)
	DEF += -DWOLFHSM_CFG_SHE_EXTENSION
endif

# Enable per-client crypto affinity (HW/SW devId selection) and its unit test
ifeq ($(CRYPTO_AFFINITY),1)
	DEF += -DWOLFHSM_CFG_CRYPTO_AFFINITY
endif

# Support a TLS-capable build
ifeq ($(TLS),1)
	DEF += -DWOLFHSM_CFG_TLS
endif

# Support stress test mode (only runs thread safety stress test)
ifeq ($(STRESS),1)
    ifneq ($(THREADSAFE),1)
        $(error Stress test requires building with THREADSAFE=1)
    endif
	DEF += -DWOLFHSM_CFG_TEST_STRESS
endif

# Support an authentication-capable build
ifeq ($(AUTH),1)
	DEF += -DWOLFHSM_CFG_ENABLE_AUTHENTICATION
endif

# Support trusted-cert verify-result cache
ifeq ($(CERT_VERIFY_CACHE),1)
	DEF += -DWOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE
endif

# Use the cross-client (global) variant of the trusted-cert verify cache.
# Implies CERT_VERIFY_CACHE.
ifeq ($(CERT_VERIFY_CACHE_GLOBAL),1)
	DEF += -DWOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE
	DEF += -DWOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE_GLOBAL
endif

## Project defines
# Option to build wolfcrypt tests
ifeq ($(TESTWOLFCRYPT),1)
	DEF += -DWOLFHSM_CFG_TEST_WOLFCRYPTTEST
endif

ifeq ($(CLIENT_ONLY),1)
# Build a client-only test driver to connect to a remote server
    DEF += -DWOLFHSM_CFG_ENABLE_CLIENT
	DEF += -DWOLFHSM_CFG_TEST_CLIENT_ONLY
else
# Build both and client server
    DEF += -DWOLFHSM_CFG_ENABLE_CLIENT
	DEF += -DWOLFHSM_CFG_ENABLE_SERVER
	DEF += -DWOLFHSM_CFG_IS_TEST_SERVER
endif


## Source files
# Assembly source files
SRC_ASM +=

ifneq ($(NOCRYPTO),1)
ifeq ($(WOLFSSL_LIB),1)
# Link against an installed wolfSSL shared/static library instead of
# compiling wolfSSL/wolfCrypt sources. Set WOLFSSL_LIBDIR for non-default
# install paths. NO_INLINE keeps wolfSSL's headers C90-clean (the
# in-tree user_settings.h normally provides this).
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

    # Set the defines for WC_USE_DEVID. The wolfCrypt test suite drives the
    # HSM through the always-registered global devIds (TESTWOLFCRYPT_DEVID
    # defaults to WH_DEV_ID; TESTWOLFCRYPT_DMA uses WH_DEV_ID_DMA).
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

# Test source files
SRC_C +=  $(wildcard $(PROJECT_DIR)/*.c)


## Automated processing below

FILENAMES_C = $(notdir $(SRC_C))
OBJS_C = $(addprefix $(BUILD_DIR)/, $(FILENAMES_C:.c=.o))
vpath %.c $(dir $(SRC_C))

OBJS_ASM = $(addprefix $(BUILD_DIR)/, $(notdir $(SRC_ASM:.s=.o)))
vpath %.s $(dir $(SRC_ASM))


## Makefile Targets

.PHONY: build_app build_hex build_static clean run coverage coverage-json

build_app: $(BUILD_DIR) $(BUILD_DIR)/$(BIN).elf
	@echo Build complete.

build_hex: $(BUILD_DIR) $(BUILD_DIR)/$(BIN).hex
	@echo ""
	$(CMD_ECHO) $(SIZE) $(BUILD_DIR)/$(BIN).elf

build_static: $(BUILD_DIR) $(BUILD_DIR)/$(BIN).a
	@echo ""
	$(CMD_ECHO) $(SIZE) $(BUILD_DIR)/$(BIN).a

analyze:$(OBJS_ASM) $(OBJS_C)

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

# Wire-format struct-padding audit. -Wpadded turns spurious padding into a
# build error. WH_PADDING_CHECK is an internal sentinel honored by
# wh_settings.h that suppresses external dependencies (wolfSSL etc.) so the
# audit doesn't drag in third-party source whose layout could perturb the
# result. Distinct from WOLFHSM_CFG_NO_CRYPTO so it doesn't disable user
# features (e.g. the cert verify cache).
$(BUILD_DIR)/wh_test_check_struct_padding.o: CFLAGS+=-Wpadded -DWH_PADDING_CHECK

$(BUILD_DIR)/%.o: %.c
	@echo "Compiling C file: $(notdir $<)"
	$(CMD_ECHO) $(CC) $(CFLAGS) $(DEF) $(INC) -c -o $@ $<

# Include auto-generated dependency files (if they exist)
-include $(OBJS_C:.o=.d)

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
			$(BUILD_DIR)/*.d \
			$(BUILD_DIR)/*.a \
			$(BUILD_DIR)/*.sym \
			$(BUILD_DIR)/*.disasm \
			$(BUILD_DIR)/*.gcda \
			$(BUILD_DIR)/*.gcno

# Rebuild if sources or flags changed before running
run: build_app
ifeq ($(TSAN),1)
	# TSAN options:
	# - fail fast on first data race detected
	# - non-zero exit code if races are detected to ensure CI fails
	# - use our custom suppressions file to ignore wolfCrypt and SHM transport
	TSAN_OPTIONS="halt_on_error=1:exitcode=66:suppressions=$(PROJECT_DIR)/tsan.supp" $(BUILD_DIR)/$(BIN).elf
else
	$(BUILD_DIR)/$(BIN).elf
endif

# Coverage target: build with coverage, run tests, and generate report
coverage:
	@echo "Building with coverage enabled..."
	$(MAKE) clean
	$(eval COVERAGE_TARGETS := $(filter-out coverage,$(MAKECMDGOALS)))
	$(MAKE) COVERAGE=1 $(if $(COVERAGE_TARGETS),$(COVERAGE_TARGETS),build_app)
	@echo "Running tests..."
	@if [ ! -f $(BUILD_DIR)/$(BIN).elf ]; then \
		echo "Error: $(BUILD_DIR)/$(BIN).elf not found. Build failed."; \
		exit 1; \
	fi
	$(BUILD_DIR)/$(BIN).elf
	@echo "Generating coverage report..."
	mkdir -p ../coverage && gcovr Build \
		--gcov-ignore-parse-errors="negative_hits.warn" \
		--root .. \
		--gcov-executable gcov \
		--gcov-ignore-parse-errors=negative_hits.warn_once_per_file \
		--gcov-ignore-parse-errors=suspicious_hits.warn_once_per_file \
		--filter '\.\./src/.*' \
		--filter '\.\./wolfhsm/.*' \
		--html-details ../coverage/index.html \
		--print-summary
	@echo "Coverage report generated at ../coverage/index.html"

# Coverage tracefile target: build with coverage, run tests, emit JSON tracefile
# to $(OUT). Designed for CI matrix runs where multiple configs each emit a
# tracefile and a downstream step merges them with `gcovr --add-tracefile`.
coverage-json:
	@if [ -z "$(OUT)" ]; then \
		echo "Error: must set OUT=path/to/tracefile.json"; \
		exit 1; \
	fi
	@echo "Building with coverage enabled..."
	$(MAKE) clean
	$(MAKE) COVERAGE=1 build_app
	@echo "Running tests..."
	$(BUILD_DIR)/$(BIN).elf
	@echo "Generating JSON tracefile at $(OUT)..."
	mkdir -p $(dir $(OUT)) && gcovr Build \
		--gcov-ignore-parse-errors=negative_hits.warn_once_per_file \
		--gcov-ignore-parse-errors=suspicious_hits.warn_once_per_file \
		--root .. \
		--filter '\.\./src/.*' \
		--filter '\.\./wolfhsm/.*' \
		--json $(OUT)

# Prevent make from trying to build these as targets
%:
	@:
