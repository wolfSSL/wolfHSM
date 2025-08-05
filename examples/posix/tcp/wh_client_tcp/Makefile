# Set to @ if you want to suppress command echo
CMD_ECHO =

# Important directories
BUILD_DIR = ./Build
WOLFHSM_DIR = $(CURDIR)/../../../../
WOLFHSM_CLIENT_DEMO_DIR = $(CURDIR)/../../../demo/client
WOLFSSL_DIR ?= $(CURDIR)/../../../../../wolfssl


# Project name
BIN = wh_client_tcp

# Includes
USER_SETTINGS_DIR ?= ./
INC = -I$(WOLFHSM_DIR) \
      -I$(USER_SETTINGS_DIR) \
      -I$(WOLFSSL_DIR) \
      -I$(WOLFHSM_CLIENT_DEMO_DIR)

# Defines
DEF = -DWOLFSSL_USER_SETTINGS -D WOLFHSM_CFG -D_GNUC_

# Architecture
ARCHFLAGS ?=

# Compiler and linker flags
ASFLAGS ?= $(ARCHFLAGS)
CFLAGS_EXTRA ?= -Wextra
CFLAGS ?= $(ARCHFLAGS) -Wno-cpp -std=c99 -Wall -Werror $(CFLAGS_EXTRA)
LDFLAGS ?= $(ARCHFLAGS)

# LD: generate map
#LDFLAGS += -Wl,-Map=$(BUILD_DIR)/$(BIN).map

# Libc for printf, libm for math
LIBS = -lc -lm

# Optimization level and place functions / data into separate sections to allow dead code removal
CFLAGS += -O0 -ffunction-sections -fdata-sections
#-fstrict-volatile-bitfields #-fno-builtin

# Remove unused sections and link time optimizations
#LDFLAGS += -Wl,--cref -Wl,--gc-sections -static -u _printf_float -Wl,--start-group $(LIBS) -Wl,--end-group -flto
#-nostartfiles #-nodefaultlibs # -nostdlib

# Debugging
DBGFLAGS = -ggdb -g3
CFLAGS += $(DBGFLAGS)
LDFLAGS += $(DBGFLAGS)

# Assembly source files
#SRC_ASM +=

#wolfCrypt source files
SRC_C += $(wildcard $(WOLFSSL_DIR)/wolfcrypt/src/*.c)

DEF += -D_POSIX_C_SOURCE=200809L -DWC_USE_DEVID=0x5748534D

#wolfCrypt test/benchmark source files
SRC_C += $(wildcard $(WOLFSSL_DIR)/wolfcrypt/test/*.c)
SRC_C += $(wildcard $(WOLFSSL_DIR)/wolfcrypt/benchmark/*.c)

#wolfSSL source files
#SRC_C += $(wildcard $(WOLFSSL_DIR)/src/*.c)

# wolfHSM source files
SRC_C += $(wildcard $(WOLFHSM_DIR)/src/*.c)

# WolfHSM port\HAL code
SRC_C += $(WOLFHSM_DIR)/port/posix/posix_transport_tcp.c

# Demo client code
SRC_C += $(wildcard $(WOLFHSM_CLIENT_DEMO_DIR)/*.c) 

# APP
SRC_C += ./src/wh_client_tcp.c


FILENAMES_C = $(notdir $(SRC_C))
#FILENAMES_C := $(filter-out evp.c, $(FILENAMES_C))
OBJS_C = $(addprefix $(BUILD_DIR)/, $(FILENAMES_C:.c=.o))
vpath %.c $(dir $(SRC_C))

OBJS_ASM = $(addprefix $(BUILD_DIR)/, $(notdir $(SRC_ASM:.s=.o)))
vpath %.s $(dir $(SRC_ASM))


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


