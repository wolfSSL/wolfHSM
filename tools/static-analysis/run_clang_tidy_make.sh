#!/bin/bash

# Clang-tidy runner using make integration approach
# Based on wolfSSL's testing/git-hooks/wolfssl-multi-test.sh implementation

set -e

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Output directory
OUTPUT_DIR="$SCRIPT_DIR/reports"
mkdir -p "$OUTPUT_DIR"

# Check if clang-tidy is installed
if ! command -v clang-tidy &> /dev/null; then
    echo "Error: clang-tidy is not installed or not in PATH"
    exit 1
fi

echo "Using clang-tidy version: $(clang-tidy --version | head -n 1)"

# Check if clang is installed
if ! command -v clang &> /dev/null; then
    echo "Error: clang is not installed or not in PATH"
    exit 1
fi

# Set up environment variables for clang/clang-tidy binaries
export CLANG_TIDY="$(command -v clang-tidy)"
export CLANG="$(command -v clang)"

# Rely on repo-root .clang-tidy for checks/config and header filter.
# No inline -config/-checks here to keep maintenance simple and IDEs consistent.

# Clear output files
> "$OUTPUT_DIR/clang_tidy_output.txt"
> "$OUTPUT_DIR/clang_tidy_summary.txt"

echo "Running clang-tidy analysis using make integration..."

# Change to project root
cd "$PROJECT_ROOT"

# Run make with the wrapper compiler
echo "Building with clang-tidy analysis..."

# First clean the build
make -C test clean > /dev/null 2>&1 || true

# Set up the build environment
export CC="$SCRIPT_DIR/clang-tidy-builder.sh"
export WOLFSSL_DIR="$PROJECT_ROOT/wolfssl"
export USER_SETTINGS_DIR="$PROJECT_ROOT/test/config"

# Run the build with clang-tidy wrapper
# Capture both stdout and stderr
set +e  # Don't exit on error

# Run make and capture output
make -C test 2>&1 | tee "$OUTPUT_DIR/clang_tidy_output.txt"

BUILD_RESULT=${PIPESTATUS[0]}
set -e

# Process the output to create a summary
echo "Processing results..."

# Extract errors and warnings (excluding notes)
grep -E "^[^:]+\.(c|h):[0-9]+:[0-9]+: (error|warning):" "$OUTPUT_DIR/clang_tidy_output.txt" > "$OUTPUT_DIR/clang_tidy_summary.txt" 2>/dev/null || true

# Count issues
ERROR_COUNT=$(grep -c " error:" "$OUTPUT_DIR/clang_tidy_summary.txt" 2>/dev/null) || ERROR_COUNT=0
WARNING_COUNT=$(grep -c " warning:" "$OUTPUT_DIR/clang_tidy_summary.txt" 2>/dev/null) || WARNING_COUNT=0
TOTAL_ISSUES=$((ERROR_COUNT + WARNING_COUNT))

echo ""
echo "Static analysis complete!"
echo "Full output: $OUTPUT_DIR/clang_tidy_output.txt"
echo "Summary: $OUTPUT_DIR/clang_tidy_summary.txt"
echo ""
echo "Results:"
echo "  Errors: $ERROR_COUNT"
echo "  Warnings: $WARNING_COUNT"
echo "  Total issues: $TOTAL_ISSUES"

# Exit with error if we have errors or build failed
if [ $BUILD_RESULT -ne 0 ]; then
    echo ""
    echo "❌ clang-tidy build/analysis failed (make exit: $BUILD_RESULT)"
    exit $BUILD_RESULT
elif [ $ERROR_COUNT -gt 0 ]; then
    echo ""
    echo "❌ clang-tidy found $ERROR_COUNT error(s) that must be fixed"
    exit 1
elif [ $WARNING_COUNT -gt 0 ]; then
    echo ""
    echo "⚠️ clang-tidy found $WARNING_COUNT warning(s) - consider fixing these"
    exit 0  # Exit success for now, can change to exit 1 to enforce warnings
else
    echo ""
    echo "✅ clang-tidy analysis passed - no issues found"
    exit 0
fi
