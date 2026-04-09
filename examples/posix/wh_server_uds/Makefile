## Makefile for wh_server_uds — wolfHSM PKCS#11 daemon
##
## Build requirements:
##   wolfSSL source tree  at $(WOLFSSL_DIR)  (default: ../../../../wolfssl)
##   wolfHSM source tree  at $(WOLFHSM_DIR)  (default: ../../../)
##   wolfPKCS11 source    at $(WOLFPKCS11_DIR) (default: ~/wolfpkcs11)
##   p11-kit development headers: pkg-config p11-kit-1
##
## Usage:
##   make                         # build with default settings
##   make DEBUG=1                 # debug build
##   make WOLFPKCS11_DIR=/path    # custom wolfPKCS11 location
##   make run                     # build and run (sends SIGTERM after 5s)
##   make clean

BIN = wh_server_uds

PROJECT_DIR     ?= .
WOLFSSL_DIR     ?= ../../../../wolfssl
WOLFHSM_DIR     ?= ../../../
WOLFHSM_PORT_DIR ?= $(WOLFHSM_DIR)/port/posix
WOLFHSM_PKCS11_PORT_DIR ?= $(WOLFHSM_DIR)/port/pkcs11
WOLFPKCS11_DIR  ?= $(HOME)/wolfpkcs11
BUILD_DIR       ?= $(PROJECT_DIR)/Build

# p11-kit: required; fail fast if not installed
P11KIT_CFLAGS  := $(shell pkg-config --cflags p11-kit-1 2>/dev/null)
P11KIT_LIBS    := $(shell pkg-config --libs   p11-kit-1 2>/dev/null)
ifeq ($(P11KIT_CFLAGS),)
    $(error "p11-kit-1 not found via pkg-config; install libp11-kit-dev")
endif

INC = \
    -I$(PROJECT_DIR) \
    -I$(WOLFSSL_DIR) \
    -I$(WOLFHSM_DIR) \
    -I$(WOLFHSM_PORT_DIR) \
    -I$(WOLFHSM_PKCS11_PORT_DIR)/.. \
    -I$(WOLFPKCS11_DIR) \
    $(P11KIT_CFLAGS)

# Required defines
DEF += -D_POSIX_C_SOURCE=200809L
DEF += -DWOLFSSL_USER_SETTINGS -DWOLFHSM_CFG
DEF += -DP11_KIT_FUTURE_UNSTABLE_API
# Suppress wolfssl/options.h to avoid redefinitions with user_settings.h
DEF += -DWOLFSSL_NO_OPTIONS_H
# wolfPKCS11 storage and wolfHSM backend
DEF += -DWOLFPKCS11_CUSTOM_STORE
DEF += -DWOLFPKCS11_WOLFHSM

ARCHFLAGS ?=
CFLAGS    ?= $(ARCHFLAGS) -std=c99 -Wall -Wextra -Werror
LDFLAGS   ?= $(ARCHFLAGS)

OS_NAME := $(shell uname -s | tr A-Z a-z)
ifeq ($(OS_NAME),darwin)
    LDFLAGS += -Wl,-dead_strip
else
    LDFLAGS += -Wl,--gc-sections
endif

CFLAGS += -ffunction-sections -fdata-sections

ifeq ($(DEBUG),1)
    CFLAGS  += -ggdb -g3
    LDFLAGS += -ggdb -g3
    DEF     += -DWOLFHSM_CFG_DEBUG
endif

ifeq ($(ASAN),1)
    CFLAGS  += -fsanitize=address
    LDFLAGS += -fsanitize=address
endif

## Source files

# wolfCrypt
SRC_C += $(wildcard $(WOLFSSL_DIR)/wolfcrypt/src/*.c)

# wolfHSM core
SRC_C += $(wildcard $(WOLFHSM_DIR)/src/*.c)

# wolfHSM POSIX port (mem transport, flash ramsim, etc.)
SRC_C += $(wildcard $(WOLFHSM_PORT_DIR)/*.c)

# wolfHSM PKCS#11 NVM store callbacks
SRC_C += $(WOLFHSM_PKCS11_PORT_DIR)/wh_pkcs11_store.c

# wolfPKCS11 compiled from source (same flags as the rest of the build)
SRC_C += $(wildcard $(WOLFPKCS11_DIR)/src/*.c)

# Daemon main
SRC_C += $(PROJECT_DIR)/main.c

LIBS += $(P11KIT_LIBS) -lpthread


## Automated processing

FILENAMES_C = $(notdir $(SRC_C))
OBJS_C = $(addprefix $(BUILD_DIR)/, $(FILENAMES_C:.c=.o))
vpath %.c $(dir $(SRC_C))

CMD_ECHO ?=

.PHONY: build_app clean run check_wolfpkcs11

build_app: check_wolfpkcs11 $(BUILD_DIR) $(BUILD_DIR)/$(BIN)

check_wolfpkcs11:
	@if [ ! -f $(WOLFPKCS11_DIR)/src/internal.c ]; then \
	    echo ""; \
	    echo "ERROR: wolfPKCS11 source not found at $(WOLFPKCS11_DIR)"; \
	    echo ""; \
	    echo "Clone wolfPKCS11 from github.com/wolfSSL/wolfPKCS11:"; \
	    echo "  git clone https://github.com/wolfSSL/wolfPKCS11 ~/wolfpkcs11"; \
	    echo ""; \
	    echo "Or set WOLFPKCS11_DIR=/path/to/wolfpkcs11 to point to your checkout."; \
	    echo ""; \
	    exit 1; \
	fi

$(BUILD_DIR):
	$(CMD_ECHO) mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: %.c
	@echo "Compiling: $(notdir $<)"
	$(CMD_ECHO) $(CC) $(CFLAGS) $(DEF) $(INC) -c -o $@ $<

$(BUILD_DIR)/$(BIN): $(OBJS_C)
	@echo "Linking: $(notdir $@)"
	$(CMD_ECHO) $(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	@echo "Build complete: $@"

clean:
	@echo "Cleaning build files"
	@rm -f $(BUILD_DIR)/*.o $(BUILD_DIR)/*.d $(BUILD_DIR)/$(BIN)

# Quick smoke test: start daemon, wait 2s, check socket exists, send SIGTERM
run: build_app
	@echo "Starting $(BUILD_DIR)/$(BIN) (socket: $(WH_UDS_PATH))"
	$(BUILD_DIR)/$(BIN) &
	@sleep 2
	@test -S "$${WH_UDS_PATH:-/tmp/wolfhsm-pkcs11.sock}" && \
	    echo "Socket exists — daemon started OK" || \
	    echo "WARNING: socket not found"
	@kill -TERM $$(pgrep -fn $(BIN)) 2>/dev/null || true
	@wait 2>/dev/null || true
