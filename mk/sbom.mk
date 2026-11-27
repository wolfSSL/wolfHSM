# POSIX SBOM for wolfHSM. Include this file after the Makefile has
# finished its -D list.
#
# Required: WOLFHSM_DIR
# The library target `sbom` records src/*.c and the POSIX port.
# Set WOLFHSM_SBOM_APP_NAME to also record the program sources in
# this Makefile as `sbom-app`. Those sources are SRC_C with the
# wolfHSM library, the POSIX port, and wolfSSL removed.
# Set WOLFHSM_SBOM_APP_SRCS to name the program sources yourself.
# Set WOLFHSM_SBOM_CFLAGS to pass a flag list other than the compile line.
# NOCRYPTO=1 records no wolfSSL dependency.

ifeq ($(WOLFHSM_DIR),)
$(error mk/sbom.mk needs WOLFHSM_DIR)
endif

_WH_SBOM_ROOT := $(abspath $(WOLFHSM_DIR))
_WH_SBOM_PORT := $(if $(WOLFHSM_PORT_DIR),$(abspath $(WOLFHSM_PORT_DIR)),$(_WH_SBOM_ROOT)/port/posix)

SBOM_NAME := wolfhsm
SBOM_ROOT := $(_WH_SBOM_ROOT)
SBOM_LICENSE_FILE := $(SBOM_ROOT)/LICENSE
SBOM_LICENSE_OVERRIDE := GPL-3.0-or-later
SBOM_COPYRIGHT_START := 2024
SBOM_VERSION := $(shell sed -n 's/^\# wolfHSM Release v\([0-9][0-9.]*\).*/\1/p' $(SBOM_ROOT)/ChangeLog.md | head -1)
ifeq ($(SBOM_VERSION),)
$(error ChangeLog.md has no wolfHSM Release version line)
endif
# The compile recipe is $(CC) $(CFLAGS) $(DEF) $(INC). Keep that order so
# a -D in CFLAGS and the first matching -I are the ones the build uses.
SBOM_CFLAGS := $(if $(WOLFHSM_SBOM_CFLAGS),$(WOLFHSM_SBOM_CFLAGS),$(CFLAGS) $(DEF) $(INC))
SBOM_SETTINGS_H := $(SBOM_ROOT)/wolfhsm/wh_settings.h
SBOM_INCLUDE_DIRS :=
ifneq ($(CONFIG_DIR),)
SBOM_INCLUDE_DIRS += $(abspath $(CONFIG_DIR))
endif
SBOM_INCLUDE_DIRS += $(abspath $(CURDIR)) $(SBOM_ROOT) $(_WH_SBOM_PORT)
ifneq ($(WOLFSSL_DIR),)
SBOM_INCLUDE_DIRS += $(abspath $(WOLFSSL_DIR))
endif
SBOM_SRCS := $(wildcard $(SBOM_ROOT)/src/*.c) $(wildcard $(_WH_SBOM_PORT)/*.c)
SBOM_MACRO_PREFIX := WOLFHSM_
ifeq ($(NOCRYPTO),1)
SBOM_DEP_WOLFSSL := no
else
SBOM_DEP_WOLFSSL := yes
SBOM_DEP_WOLFCRYPT := yes
endif

ifneq ($(WOLFHSM_SBOM_APP_NAME),)
ifeq ($(WOLFHSM_SBOM_APP_SRCS),)
_WH_SBOM_DROP := $(abspath $(WOLFHSM_DIR)/src)/% $(_WH_SBOM_PORT)/%
ifneq ($(WOLFSSL_DIR),)
_WH_SBOM_DROP += $(abspath $(WOLFSSL_DIR))/%
endif
WOLFHSM_SBOM_APP_SRCS := $(filter-out $(_WH_SBOM_DROP),$(abspath $(SRC_C)))
endif
SBOM_APP_NAME := $(WOLFHSM_SBOM_APP_NAME)
SBOM_APP_ROOT := $(SBOM_ROOT)
SBOM_APP_LICENSE_FILE := $(SBOM_LICENSE_FILE)
SBOM_APP_LICENSE_OVERRIDE := $(SBOM_LICENSE_OVERRIDE)
SBOM_APP_COPYRIGHT_START := $(SBOM_COPYRIGHT_START)
SBOM_APP_VERSION := $(SBOM_VERSION)
SBOM_APP_CFLAGS := $(SBOM_CFLAGS)
SBOM_APP_SETTINGS_H := $(SBOM_SETTINGS_H)
SBOM_APP_INCLUDE_DIRS := $(SBOM_INCLUDE_DIRS)
SBOM_APP_MACRO_PREFIX := $(SBOM_MACRO_PREFIX)
SBOM_APP_DEP_WOLFSSL := $(SBOM_DEP_WOLFSSL)
SBOM_APP_DEP_WOLFCRYPT := $(SBOM_DEP_WOLFCRYPT)
SBOM_APP_COMPONENT_TYPE := application
SBOM_APP_SRCS := $(abspath $(WOLFHSM_SBOM_APP_SRCS))
endif

include $(SBOM_ROOT)/tools/sbom/build/sbom.mk

ifneq ($(WOLFHSM_SBOM_APP_NAME),)
$(eval $(call wolfssl_compliance_tooling_sbom_rule,sbom-app,SBOM_APP_))
endif
