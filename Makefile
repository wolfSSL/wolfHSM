
.PHONY: all test benchmark tools examples clean

export DEBUG
export DEBUG_VERBOSE
export AUTH

all: test benchmark tools examples

test:
	make -C test

benchmark:
	make -C benchmark

tools:
	make -C tools

examples:
	make -C examples

SCAN_DIR = ./scan_out

scan_result_check:
	@err=$$(grep -h -o 'error: .*' ./$(SCAN_DIR)/*.log | wc -l); \
	if [ -z "$$err" ]; then \
		err=0; \
	fi; \
	wrn=$$(grep -h -o '^[0-9]\+ warnings\? generated' ./$(SCAN_DIR)/*.log | grep -o '^[0-9]\+' | awk '{s+=$$1} END {print s}');\
	if [ -z "$$wrn" ]; then \
		wrn=0; \
	fi; \
	if [ $$err -eq 0 -a $$wrn -eq 0 ]; then \
		echo "no errors or warnings found";\
		exit 0; \
	else\
		echo "scan-build detected $$err errors and $$wrn warnings";\
		for f in $(SCAN_DIR)/*.log; do \
			echo "---- $$f ----"; \
			cat $$f; \
			echo ""; \
		done; \
		exit 1; \
	fi;

scan:
	@echo "Running scan-build static analysis"
	@rm -rf $(SCAN_DIR)
	@mkdir -p $(SCAN_DIR)
	@make clean
	-@make -j SCAN=1 -C test scan
	@$(MAKE) scan_result_check

clean:
	make -C test clean
	make -C benchmark clean
	make -C tools clean
	make -C examples clean

# ---- SBOM generation (vendored wolfGlass driver) ----
# Version comes from ChangeLog.md: there is no release version macro in the
# public headers (WOLFHSM_CFG_INFOVERSION is a protocol info string, not the
# product release). Parsing ChangeLog.md is a known fragility to fix later.
#
# Config capture MUST use SBOM_OPTIONS_H, not SBOM_CFLAGS. The driver's
# --cflags path keeps only -D tokens and drops -I / -include, so feeding
# `-include wolfhsm/wh_settings.h` via SBOM_CFLAGS produced an empty SBOM
# (two raw -D flags). Capture the expanded header the same way PR #414 did.
WOLFSSL_DIR     ?= ../wolfssl
HOSTCC          ?= cc
SBOM_NAME       := wolfhsm
SBOM_ROOT       := $(CURDIR)
SBOM_SRCS       := $(sort $(wildcard src/*.c))
SBOM_VERSION    := $(shell sed -n 's/^. wolfHSM Release v//p' ChangeLog.md | head -1 | cut -d' ' -f1)
SBOM_LICENSE_FILE := $(CURDIR)/LICENSING
SBOM_DEP_WOLFSSL  ?= yes
SBOM_OPTIONS_H  := $(CURDIR)/.sbom-wolfhsm-defines.h

# Enforce only when an SBOM goal was actually requested. A bare $(error) here
# is evaluated while the Makefile is read, so it aborts every goal in the tree
# — `make scan`, `make clean`, `make test` — not just the SBOM ones.
ifneq (,$(filter sbom sbom-defines,$(MAKECMDGOALS)))
ifeq ($(origin WOLFHSM_CFG_DIR),undefined)
$(error WOLFHSM_CFG_DIR is required — point it at the directory \
holding the wolfhsm_cfg.h/user_settings.h your build uses; do \
not assume test/config is a release configuration)
endif
endif

include tools/sbom/build/sbom.mk

# Keep only project configuration macros. A raw -dM dump also carries the host
# compiler's own builtins, and gen-sbom's scrub drops __-prefixed names but not
# system macros whose *values* name them (ATOMIC_BOOL_LOCK_FREE expands to
# __GCC_ATOMIC_BOOL_LOCK_FREE under gcc, __CLANG_ATOMIC_BOOL_LOCK_FREE under
# clang), which made the SBOM toolchain-dependent.
#
# Object-like macros only: the trailing [[:space:]] excludes function-like ones,
# whose bodies differ cosmetically between the two preprocessors ("idx ##VAR"
# vs "idx##VAR"). A macro body is an implementation detail, not build config.
#
# The \# is required: an unescaped # would start a Make comment and silently
# truncate this pattern to "^", which matches every line and filters nothing.
SBOM_DEFINE_RE := ^\#define (WOLFHSM|WOLFSSL|WOLFCRYPT|WOLF|WC_|HAVE_|NO_|OPENSSL|USE_|SIZEOF_|FP_|TFM_|SP_|ECC_|RSA_|AES_|SHA|CURVE|ED25519|ED448|HKDF|KEEP_|SMALL_|BIG_|NDEBUG|DEBUG)[A-Za-z0-9_]*[[:space:]]

# Always re-capture: a stale dump would hide config changes. The driver's
# --cflags path cannot do this — it drops -I/-include.
.PHONY: sbom-defines
sbom-defines:
	@echo "SBOM: capturing config via $(HOSTCC) -dM -E -include wolfhsm/wh_settings.h"
	@$(HOSTCC) -dM -E -DWOLFHSM_CFG -DWOLFSSL_USER_SETTINGS \
	    -I. -I$(WOLFHSM_CFG_DIR) -I$(WOLFSSL_DIR) \
	    -include wolfhsm/wh_settings.h -x c /dev/null \
	  | LC_ALL=C grep -E '$(SBOM_DEFINE_RE)' \
	  | LC_ALL=C sort > $(SBOM_OPTIONS_H)
	@if [ ! -s $(SBOM_OPTIONS_H) ]; then \
	    echo "ERROR: captured no configuration macros from" >&2; \
	    echo "       WOLFHSM_CFG_DIR=$(WOLFHSM_CFG_DIR)" >&2; \
	    echo "       Check that it holds the wolfhsm_cfg.h/user_settings.h" >&2; \
	    echo "       your build uses." >&2; \
	    rm -f $(SBOM_OPTIONS_H); \
	    exit 1; \
	fi

sbom: sbom-defines
