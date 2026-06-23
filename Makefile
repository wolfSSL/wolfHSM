
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
WOLFSSL_DIR   ?= ../../wolfssl
VERSION       := $(shell sed -n 's/^# wolfHSM Release v\([0-9][0-9.]*\).*/\1/p' ChangeLog.md | head -1)
SRCS          := $(wildcard src/*.c)
SBOM_CDX      := wolfhsm-$(VERSION).cdx.json
SBOM_SPDX     := wolfhsm-$(VERSION).spdx.json

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
	    echo "       Use a wolfSSL tree that includes SBOM support." >&2; \
	    exit 1; \
	fi
	@echo "wolfHSM version: $(VERSION)"
	@echo "Sources:         $(words $(SRCS)) .c files in src/"
	@_defines=$$(mktemp /tmp/wolfhsm-defines.XXXXXX) && \
	trap 'rm -f "$$_defines"' EXIT && \
	if ! $(CC) -dM -E -I. -I$(WOLFSSL_DIR) -x c /dev/null >"$$_defines" 2>/dev/null; then \
	    echo "ERROR: $(CC) -dM -E failed." >&2; exit 1; \
	fi && \
	_py=$$(command -v python3 2>/dev/null || command -v python 2>/dev/null) && \
	[ -n "$$_py" ] || { echo "ERROR: python3 not found." >&2; exit 1; } && \
	"$$_py" $(WOLFSSL_DIR)/scripts/gen-sbom \
	    --name wolfhsm \
	    --version $(VERSION) \
	    --supplier "wolfSSL Inc." \
	    --license-file LICENSING \
	    --options-h "$$_defines" \
	    --srcs $(SRCS) \
	    --cdx-out $(SBOM_CDX) \
	    --spdx-out $(SBOM_SPDX)
	@echo "Done: $(SBOM_CDX)  $(SBOM_SPDX)"
