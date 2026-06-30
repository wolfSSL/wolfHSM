## Makefile for wolfHSM test-refactor POSIX port
## Mirrors test/Makefile conventions with minimal sources

# Use bash so the `run` target can read ${PIPESTATUS[0]} to get
# the test binary's exit status through `tee`.
SHELL := /bin/bash

## Project name
BIN = wh_test_refactor

## Important directories
PROJECT_DIR      ?= .
REFACTOR_DIR     ?= $(PROJECT_DIR)/..
CONFIG_DIR       ?= $(REFACTOR_DIR)/../test/config
REFACTOR_CFG_DIR ?= $(REFACTOR_DIR)/config
WOLFSSL_DIR      ?= ../../../wolfssl
WOLFHSM_DIR      ?= $(REFACTOR_DIR)/..
WOLFHSM_PORT_DIR ?= $(WOLFHSM_DIR)/port/posix
TEST_DIR         ?= $(WOLFHSM_DIR)/test

BUILD_DIR        ?= $(PROJECT_DIR)/Build

# Includes
INC =   -I$(PROJECT_DIR) \
        -I$(REFACTOR_DIR) \
        -I$(REFACTOR_DIR)/server \
        -I$(REFACTOR_DIR)/client-server \
        -I$(REFACTOR_DIR)/misc \
        -I$(REFACTOR_CFG_DIR) \
        -I$(CONFIG_DIR) \
        -I$(TEST_DIR) \
        -I$(WOLFSSL_DIR) \
        -I$(WOLFHSM_DIR) \
        -I$(WOLFHSM_PORT_DIR)

# POSIX requires C source be defined before any header
DEF += -D_POSIX_C_SOURCE=200809L

# Library configuration defines for user-supplied settings
DEF += -DWOLFSSL_USER_SETTINGS -DWOLFHSM_CFG

# Enable POSIX test features and server
DEF += -DWOLFHSM_CFG_TEST_POSIX
DEF += -DWOLFHSM_CFG_ENABLE_CLIENT
DEF += -DWOLFHSM_CFG_ENABLE_SERVER

# C standard
CSTD        ?= -std=c90

# Compiler flags
CFLAGS_EXTRA = -Werror -Wall -Wextra
CFLAGS_EXTRA += -ffunction-sections -fdata-sections
CFLAGS_EXTRA += -MMD -MP

ARCHFLAGS ?=
CFLAGS    ?= $(ARCHFLAGS) $(CSTD) $(CFLAGS_EXTRA)
LDFLAGS   ?= $(ARCHFLAGS)

# Dead-strip unused sections
OS_NAME := $(shell uname -s | tr A-Z a-z)
ifeq ($(OS_NAME),darwin)
    LDFLAGS += -Wl,-dead_strip
else
    LDFLAGS += -Wl,--gc-sections
endif

## Optional flags (same as test/Makefile)

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

# ThreadSanitizer. Enables the acquire/release transport shims in the
# concurrent tests (WOLFHSM_CFG_TEST_STRESS_TSAN) so TSAN's analysis stays on
# keystore/NVM locking rather than transport false positives.
ifeq ($(TSAN),1)
    ifeq ($(ASAN),1)
        $(error TSAN and ASAN cannot be used together)
    endif
    CFLAGS += -fsanitize=thread -fPIE
    LDFLAGS += -fsanitize=thread -pie
    DEF += -DWOLFSSL_NO_FENCE -DWOLFHSM_CFG_TEST_STRESS_TSAN
endif

# Enable threadsafe mode, adding lock protection to shared structures
ifeq ($(THREADSAFE),1)
    DEF += -DWOLFHSM_CFG_THREADSAFE
endif

# Build without crypto support
ifeq ($(NOCRYPTO),1)
    DEF += -DWOLFHSM_CFG_NO_CRYPTO
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

# Support an authentication-capable build
ifeq ($(AUTH),1)
    DEF += -DWOLFHSM_CFG_ENABLE_AUTHENTICATION
endif

# Enable per-client crypto affinity (HW/SW devId selection) and its unit test
ifeq ($(CRYPTO_AFFINITY),1)
    DEF += -DWOLFHSM_CFG_CRYPTO_AFFINITY
endif

# Build the wolfCrypt test suite as a wolfHSM client
ifeq ($(TESTWOLFCRYPT),1)
    DEF += -DWOLFHSM_CFG_TEST_WOLFCRYPTTEST
endif

# Add code coverage option
ifeq ($(COVERAGE),1)
    CFLAGS += --coverage
    LDFLAGS += --coverage
endif

## Source files

ifneq ($(NOCRYPTO),1)
# wolfCrypt
SRC_C += $(wildcard $(WOLFSSL_DIR)/wolfcrypt/src/*.c)

# wolfSSL TLS (needed by cert manager APIs)
SRC_C += $(wildcard $(WOLFSSL_DIR)/src/*.c)

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
        # Hardcoded DMA devId
        TESTWOLFCRYPT_DEVID = 0x57444D41
    endif

    TESTWOLFCRYPT_DEVID ?= $(TESTWOLFCRYPT_DEFAULT_DEVID)

    # The wolfCrypt test suite drives the HSM through the always-registered
    # global devIds (TESTWOLFCRYPT_DEVID defaults to WH_DEV_ID;
    # TESTWOLFCRYPT_DMA uses WH_DEV_ID_DMA).
    DEF += -DWC_USE_DEVID=$(TESTWOLFCRYPT_DEVID)

    # wolfCrypt test source files
    SRC_C += $(wildcard $(WOLFSSL_DIR)/wolfcrypt/test/*.c)
endif
endif

# wolfHSM library
SRC_C += $(wildcard $(WOLFHSM_DIR)/src/*.c)

# POSIX port (timestamps, flash file, etc.)
SRC_C += $(wildcard $(WOLFHSM_PORT_DIR)/*.c)

# Portable test-refactor sources (groups + hand-maintained registry).
SRC_C += $(REFACTOR_DIR)/wh_test_groups.c
SRC_C += $(REFACTOR_DIR)/wh_test_list.c

# Grouped test sources
SRC_C += $(wildcard $(REFACTOR_DIR)/server/*.c)
SRC_C += $(wildcard $(REFACTOR_DIR)/client-server/*.c)
SRC_C += $(wildcard $(REFACTOR_DIR)/misc/*.c)

# POSIX-specific sources (main, server/client bringup)
SRC_C += $(wildcard $(PROJECT_DIR)/*.c)

# Legacy POSIX stress test pulled from test/; the .c file is
# self-gated on WOLFHSM_CFG_THREADSAFE et al. so it compiles to
# an empty TU when the gate isn't satisfied.
SRC_C += $(TEST_DIR)/wh_test_posix_threadsafe_stress.c

# Shared NVM backend selector pulled from test/; provides
# whTest_NvmCfgBackend for tests that exercise multiple NVM
# backends (flash and flash-log).
SRC_C += $(TEST_DIR)/wh_test_common.c

# Shared keywrap test helpers pulled from test/; provides the
# trusted-KEK test bytes and the SHE wrapped-blob builder.
SRC_C += $(TEST_DIR)/wh_test_keywrap_util.c


## Build rules

FILENAMES_C = $(notdir $(SRC_C))
OBJS_C = $(addprefix $(BUILD_DIR)/, $(FILENAMES_C:.c=.o))
vpath %.c $(dir $(SRC_C))

.PHONY: build_app clean run check coverage coverage-json

build_app: $(BUILD_DIR) $(BUILD_DIR)/$(BIN).elf
	@echo Build complete.

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Workaround: pre-existing warnings in upstream files that
# -Werror promotes to errors.
$(BUILD_DIR)/internal.o: CFLAGS += -Wno-error=implicit-function-declaration
$(BUILD_DIR)/wh_client_crypto.o: CFLAGS += -Wno-error=sign-compare

# Special case: compile-only struct padding check using -Wpadded
$(BUILD_DIR)/wh_test_check_struct_padding.o: CFLAGS += -Wpadded -DWH_PADDING_CHECK

$(BUILD_DIR)/%.o: %.c
	@echo "Compiling: $(notdir $<)"
	$(CC) $(CFLAGS) $(DEF) $(INC) -c -o $@ $<

-include $(OBJS_C:.o=.d)

$(BUILD_DIR)/$(BIN).elf: $(OBJS_C)
	@echo "Linking: $(notdir $@)"
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	@echo "Cleaning build files"
	@rm -rf $(BUILD_DIR)
	@rm -f test-suite.log

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
	mkdir -p ../../coverage-refactor && gcovr Build \
		--gcov-ignore-parse-errors="negative_hits.warn" \
		--root ../.. \
		--gcov-executable gcov \
		--gcov-ignore-parse-errors=negative_hits.warn_once_per_file \
		--gcov-ignore-parse-errors=suspicious_hits.warn_once_per_file \
		--filter '\.\./\.\./src/.*' \
		--filter '\.\./\.\./wolfhsm/.*' \
		--html-details ../../coverage-refactor/index.html \
		--print-summary
	@echo "Coverage report generated at ../../coverage-refactor/index.html"

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
		--root ../.. \
		--filter '\.\./\.\./src/.*' \
		--filter '\.\./\.\./wolfhsm/.*' \
		--json $(OUT)

# Under TSAN: fail fast and non-zero on any detected race, using the shared
# suppressions (wolfCrypt internals + SHM transport).
ifeq ($(TSAN),1)
    RUN_ENV = TSAN_OPTIONS="halt_on_error=1:exitcode=66:suppressions=$(TEST_DIR)/tsan.supp"
else
    RUN_ENV =
endif

# Send the full test output to test-suite.log, not just the summary
check run: build_app
	@rm -f test-suite.log
	@$(RUN_ENV) $(BUILD_DIR)/$(BIN).elf 2>&1 \
	    | tee test-suite.log \
	    | grep --line-buffered -E \
	        '^whTest_|^All [0-9]+ tests passed|^[0-9]+ passed, [0-9]+ skipped'; \
	    rc=$${PIPESTATUS[0]}; \
	    if [ $$rc -ne 0 ]; then \
	        echo "test run exited $$rc (see test-suite.log for full output)"; \
	    fi; \
	    exit $$rc

# Prevent make from trying to build these as targets
%:
	@:
