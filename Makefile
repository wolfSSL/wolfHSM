
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

# ---- SBOM generation ----
CC            ?= cc
WOLFSSL_DIR   ?= ../wolfssl
WOLFHSM_CFG_DIR ?= test/config
VERSION        = $(shell sed -n 's/^. wolfHSM Release v//p' ChangeLog.md | head -1 | cut -d' ' -f1)
SRCS          := $(sort $(wildcard src/*.c))
SBOM_CDX       = wolfhsm-$(VERSION).cdx.json
SBOM_SPDX      = wolfhsm-$(VERSION).spdx.json

.PHONY: sbom

sbom:
	@if [ -z "$(VERSION)" ]; then \
	    echo "ERROR: could not parse version from ChangeLog.md." >&2; \
	    exit 1; \
	fi
	@if [ -z "$(WOLFSSL_DIR)" ] || [ ! -d "$(WOLFSSL_DIR)" ]; then \
	    echo "ERROR: WOLFSSL_DIR=$(WOLFSSL_DIR) is not a directory." >&2; \
	    echo "       Set WOLFSSL_DIR to your wolfssl source tree." >&2; \
	    exit 1; \
	fi
	@if [ ! -f "$(WOLFSSL_DIR)/scripts/gen-sbom" ]; then \
	    echo "ERROR: $(WOLFSSL_DIR)/scripts/gen-sbom not found." >&2; \
	    echo "       The sbom target needs a wolfSSL source tree that includes" >&2; \
	    echo "       scripts/gen-sbom (wolfSSL PR #10343, pending a future release)." >&2; \
	    echo "       Set WOLFSSL_DIR to such a tree." >&2; \
	    exit 1; \
	fi
	@if [ ! -f "$(WOLFHSM_CFG_DIR)/wolfhsm_cfg.h" ]; then \
	    echo "ERROR: $(WOLFHSM_CFG_DIR)/wolfhsm_cfg.h not found." >&2; \
	    echo "       Set WOLFHSM_CFG_DIR to the directory holding the" >&2; \
	    echo "       wolfhsm_cfg.h (and user_settings.h) your build uses." >&2; \
	    exit 1; \
	fi
	@echo "wolfHSM version: $(VERSION)"
	@echo "Sources:         $(words $(SRCS)) .c files in src/"
	@echo "Config:          $(WOLFHSM_CFG_DIR)/wolfhsm_cfg.h"
# Effective build config for the SBOM: preprocess wolfhsm/wh_settings.h with
# the same defines and include path the test build compiles under, so the -dM
# dump holds every WOLFHSM_CFG_* option (explicit and defaulted) plus the
# wolfSSL options from user_settings.h — the configuration the library is
# actually built with. Point WOLFHSM_CFG_DIR at the directory holding your
# build's wolfhsm_cfg.h/user_settings.h for an integrator-accurate SBOM.
#
# ponytail: wh_settings.h pulls libc headers (stdint/stdio/strings/stdatomic),
# so ~330 toolchain constants (INT16_MAX, ACCESSPERMS, ...) ride along into
# the SBOM next to the ~175 real config macros. The dump is deliberately NOT
# filtered here: a prefix allowlist would silently drop real options that
# carry no standard prefix (GCM_TABLE_4BIT, FP_MAX_BITS, SINGLE_THREADED).
# The durable fix belongs in gen-sbom's noise filter (wolfSSL PR #10343,
# scripts/gen-sbom _NOISE_MACRO_RE), either of:
#   a) provenance filtering: accept a -dD dump and use its #line markers to
#      drop macros defined in system headers, or
#   b) an --options-baseline flag: subtract a second -dM dump made with the
#      same flags minus the -include, plus the libc headers it pulls.
# Once gen-sbom grows that, this recipe needs no change — it already hands
# over the full dump.
	@_defines=$$(mktemp "$${TMPDIR:-/tmp}/wolfhsm-defines.XXXXXX") && \
	trap 'rm -f "$$_defines"' 0 && \
	if ! $(CC) -dM -E -DWOLFHSM_CFG -DWOLFSSL_USER_SETTINGS \
	    -I. -I$(WOLFHSM_CFG_DIR) -I$(WOLFSSL_DIR) \
	    -include wolfhsm/wh_settings.h -x c /dev/null >"$$_defines"; then \
	    echo "ERROR: $(CC) -dM -E on wolfhsm/wh_settings.h failed." >&2; exit 1; \
	fi && \
	if ! command -v python3 >/dev/null 2>&1; then \
	    echo "ERROR: python3 not found." >&2; exit 1; \
	fi && \
	python3 $(WOLFSSL_DIR)/scripts/gen-sbom \
	    --name wolfhsm \
	    --version $(VERSION) \
	    --supplier "wolfSSL Inc." \
	    --license-file LICENSING \
	    --options-h "$$_defines" \
	    --srcs $(SRCS) \
	    --cdx-out $(SBOM_CDX) \
	    --spdx-out $(SBOM_SPDX)
	@echo "Done: $(SBOM_CDX)  $(SBOM_SPDX)"
