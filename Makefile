
.PHONY: all test benchmark tools examples clean

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
	@num=$$(grep -h -o '^[0-9]\+ warnings\? generated' ./$(SCAN_DIR)/*.log | grep -o '^[0-9]\+' | awk '{s+=$$1} END {print s}');\
	if [ -z "$$num" ]; then \
		echo "no warnings found";\
		exit 0; \
	fi; \
	if [ $$num -ne 0 ]; then \
		echo "scan-build found $$num warnings";\
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
	-@make SCAN=1 -C test scan
	-@make SCAN=1 -C benchmark scan
	-@make NOCRYPTO=1 SCAN=1 -C tools/whnvmtool scan
	-@make NOCRYPTO=1 SCAN=1 -C examples
	@$(MAKE) scan_result_check

clean:
	make -C test clean
	make -C benchmark clean
	make -C tools clean
	make -C examples clean
