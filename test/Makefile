# Set to @ if you want to suppress command echo
CMD_ECHO =

# Important directories
BUILD_DIR = ./Build
WOLFHSM_DIR = $(CURDIR)/../
WOLFSSL_DIR ?= $(CURDIR)/../../wolfssl

# Project name
BIN = wh_test

# Includes
USER_SETTINGS_DIR ?= ./
INC = -I$(WOLFHSM_DIR) \
      -I$(USER_SETTINGS_DIR) \
      -I$(WOLFSSL_DIR)

# Library configuration defines to use additional files.
DEF = -DWOLFSSL_USER_SETTINGS -DWOLFHSM_CFG

# Test program configuration
#DEF += -DWOLFHSM_CFG_TEST_VERBOSE
DEF += -DWOLFHSM_CFG_TEST_POSIX

ifeq ($(TESTWOLFCRYPT),1)
DEF += -DWOLFHSM_CFG_TEST_WOLFCRYPTTEST
endif

# Architecture
ARCHFLAGS ?=

# Compiler and linker flags
ASFLAGS ?= $(ARCHFLAGS)
CFLAGS_EXTRA ?= -Wmissing-field-initializers -Wmissing-braces
CFLAGS ?= $(ARCHFLAGS) -std=c90 -D_GNU_SOURCE -Wall -Werror -Wno-cpp $(CFLAGS_EXTRA)
LDFLAGS ?= $(ARCHFLAGS)

# LD: generate map
#LDFLAGS += -Wl,-map,$(BUILD_DIR)/$(BIN).map
#LDFLAGS += -Wl,-Map=$(BUILD_DIR)/$(BIN).map

# Libc for printf
LIBS = -lc

# Optimization level and place functions / data into separate sections to allow dead code removal
CFLAGS += -ffunction-sections -fdata-sections

# Debugging
# Check if DEBUG is set to 1 and append debug flags
ifeq ($(DEBUG),1)
DBGFLAGS = -ggdb -g3
CFLAGS += $(DBGFLAGS)
LDFLAGS += $(DBGFLAGS)
endif

ifeq ($(DEBUG_CRYPTOCB),1)
CFLAGS += -DDEBUG_CRYPTOCB
endif

ifeq ($(DEBUG_CRYPTOCB_VERBOSE),1)
CFLAGS += -DDEBUG_CRYPTOCB -DDEBUG_CRYPTOCB_VERBOSE
endif

# Add address sanitizer option
ifeq ($(ASAN),1)
CFLAGS += -fsanitize=address
LDFLAGS += -fsanitize=address
endif

# Support a NO CRYPTO build
ifeq ($(NOCRYPTO),1)
CFLAGS += -DWOLFHSM_CFG_NO_CRYPTO
endif

ifeq ($(SHE),1)
CFLAGS += -DWOLFHSM_CFG_SHE_EXTENSION
endif

# Assembly source files
SRC_ASM +=

ifneq ($(NOCRYPTO),1)
# wolfCrypt source files
SRC_C += \
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
endif

ifeq ($(TESTWOLFCRYPT),1)
    # wolfCrypt test source files
    SRC_C += $(WOLFSSL_DIR)/wolfcrypt/test/test.c
    SRC_C += $(wildcard $(WOLFSSL_DIR)/wolfcrypt/src/*.c)

    TESTWOLFCRYPT_DEFAULT_DEVID = 0x5748534D

    # TESTWOLFCRYPT_DEVID and TESTWOLFCRYPT_DMA are mutually exclusive
    ifneq ($(TESTWOLFCRYPT_DMA),)
        ifneq ($(TESTWOLFCRYPT_DEVID),)
            $(error "Cannot set both TESTWOLFCRYPT_DEVID and TESTWOLFCRYPT_DMA. Please choose one.")
        endif
        # Set TESTWOLFCRYPT_DEVID to a hardcoded value when TESTWOLFCRYPT_DMA is set
        TESTWOLFCRYPT_DEVID = 0x57444D41
    endif

    # Set default TESTWOLFCRYPT_DEVID if not defined by the user
    TESTWOLFCRYPT_DEVID ?= $(TESTWOLFCRYPT_DEFAULT_DEVID)

    # Set the CFLAGS for WC_USE_DEVID
    CFLAGS += -DWC_USE_DEVID=$(TESTWOLFCRYPT_DEVID)
endif


# wolfHSM source files
SRC_C += \
            $(WOLFHSM_DIR)/src/wh_utils.c \
            $(WOLFHSM_DIR)/src/wh_crypto.c \
            $(WOLFHSM_DIR)/src/wh_client.c \
            $(WOLFHSM_DIR)/src/wh_client_nvm.c \
            $(WOLFHSM_DIR)/src/wh_client_crypto.c \
            $(WOLFHSM_DIR)/src/wh_client_cryptocb.c \
            $(WOLFHSM_DIR)/src/wh_server.c \
            $(WOLFHSM_DIR)/src/wh_server_customcb.c \
            $(WOLFHSM_DIR)/src/wh_server_dma.c \
            $(WOLFHSM_DIR)/src/wh_server_nvm.c \
            $(WOLFHSM_DIR)/src/wh_server_crypto.c \
            $(WOLFHSM_DIR)/src/wh_server_keystore.c \
            $(WOLFHSM_DIR)/src/wh_server_counter.c \
            $(WOLFHSM_DIR)/src/wh_nvm.c \
            $(WOLFHSM_DIR)/src/wh_comm.c \
            $(WOLFHSM_DIR)/src/wh_message_comm.c \
            $(WOLFHSM_DIR)/src/wh_message_customcb.c \
            $(WOLFHSM_DIR)/src/wh_message_nvm.c \
            $(WOLFHSM_DIR)/src/wh_transport_mem.c \
            $(WOLFHSM_DIR)/src/wh_flash_ramsim.c

ifeq ($(SHE),1)
SRC_C += \
            $(WOLFHSM_DIR)/src/wh_client_she.c \
            $(WOLFHSM_DIR)/src/wh_server_she.c \
            $(WOLFHSM_DIR)/src/wh_she_common.c \
            $(WOLFHSM_DIR)/src/wh_she_crypto.c

endif

# WolfHSM port/HAL code
SRC_C += \
            $(WOLFHSM_DIR)/src/wh_nvm_flash.c \
            $(WOLFHSM_DIR)/src/wh_flash_unit.c \
            $(WOLFHSM_DIR)/src/wh_flash_ramsim.c \
            $(WOLFHSM_DIR)/src/wh_transport_mem.c \
            $(WOLFHSM_DIR)/port/posix/posix_flash_file.c \
            $(WOLFHSM_DIR)/port/posix/posix_transport_tcp.c \
            $(WOLFHSM_DIR)/port/posix/posix_transport_shm.c

# APP
SRC_C += \
            ./src/wh_test.c \
            ./src/wh_test_comm.c \
            ./src/wh_test_crypto.c \
            ./src/wh_test_she.c \
            ./src/wh_test_nvm_flash.c \
            ./src/wh_test_clientserver.c \
            ./src/wh_test_flash_ramsim.c \
            ./src/wh_test_check_struct_padding.c

ifeq ($(TESTWOLFCRYPT),1)
SRC_C += ./src/wh_test_wolfcrypt_test.c
endif

FILENAMES_C = $(notdir $(SRC_C))
#FILENAMES_C := $(filter-out evp.c, $(FILENAMES_C))
OBJS_C = $(addprefix $(BUILD_DIR)/, $(FILENAMES_C:.c=.o))
vpath %.c $(dir $(SRC_C))

OBJS_ASM = $(addprefix $(BUILD_DIR)/, $(notdir $(SRC_ASM:.s=.o)))
vpath %.s $(dir $(SRC_ASM))

.PHONY: all clean run

#Add additional flag here to avoid pragma
$(BUILD_DIR)/wh_test_check_struct_padding.o: CFLAGS+=-Wpadded -DWOLFHSM_CFG_NO_CRYPTO


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
	rm -f $(BUILD_DIR)/*.elf $(BUILD_DIR)/*.hex $(BUILD_DIR)/*.map
	rm -f $(BUILD_DIR)/*.o $(BUILD_DIR)/*.a $(BUILD_DIR)/*.sym $(BUILD_DIR)/*.disasm

run: build_app
	./$(BUILD_DIR)/$(BIN).elf

