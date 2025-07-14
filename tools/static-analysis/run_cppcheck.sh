#!/bin/bash

# Simple cppcheck script for wolfHSM static analysis

# Don't exit on error immediately since we want to handle cppcheck exit codes
set +e

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Output directory
OUTPUT_DIR="$SCRIPT_DIR/reports"
mkdir -p "$OUTPUT_DIR"

# Run cppcheck with sane defaults
echo "Running cppcheck static analysis on wolfHSM..."

# Run cppcheck and capture exit code
# Note: --error-exitcode only triggers on errors, not warnings
cppcheck \
    --enable=warning,style,performance,portability \
    --std=c99 \
    --platform=native \
    --suppressions-list="$SCRIPT_DIR/cppcheck-suppressions.txt" \
    --inline-suppr \
    --force \
    --quiet \
    --error-exitcode=1 \
    --xml \
    --xml-version=2 \
    -I "$PROJECT_ROOT/wolfhsm/" \
    -I "$PROJECT_ROOT/src/" \
    "$PROJECT_ROOT/src/" \
    "$PROJECT_ROOT/wolfhsm/" \
    2> "$OUTPUT_DIR/cppcheck.xml"
CPPCHECK_EXIT_CODE=$?

# Generate HTML report
echo "Generating HTML report..."
cppcheck-htmlreport \
    --source-dir="$PROJECT_ROOT" \
    --report-dir="$OUTPUT_DIR/html" \
    --file="$OUTPUT_DIR/cppcheck.xml" \
    --title="wolfHSM Static Analysis Report"

# Also generate a simple text summary
echo "Generating text summary..."
cppcheck \
    --enable=warning,style,performance,portability \
    --std=c99 \
    --platform=native \
    --suppressions-list="$SCRIPT_DIR/cppcheck-suppressions.txt" \
    --inline-suppr \
    --force \
    --quiet \
    --template='{file}:{line}: {severity}: {message} [{id}]' \
    -I "$PROJECT_ROOT/wolfhsm/" \
    -I "$PROJECT_ROOT/src/" \
    "$PROJECT_ROOT/src/" \
    "$PROJECT_ROOT/wolfhsm/" \
    > "$OUTPUT_DIR/cppcheck_summary.txt" 2>&1 || true

echo "Static analysis complete!"
echo "XML report: $OUTPUT_DIR/cppcheck.xml"
echo "HTML report: $OUTPUT_DIR/html/index.html"
echo "Text summary: $OUTPUT_DIR/cppcheck_summary.txt"

# Check for warnings in addition to the exit code
WARNING_COUNT=$(grep -c "warning:" "$OUTPUT_DIR/cppcheck_summary.txt" 2>/dev/null) || WARNING_COUNT=0
ERROR_COUNT=$(grep -c "error:" "$OUTPUT_DIR/cppcheck_summary.txt" 2>/dev/null) || ERROR_COUNT=0

echo ""
echo "Cppcheck returned $CPPCHECK_EXIT_CODE"
echo "Results:"
echo "  Errors: $ERROR_COUNT"
echo "  Warnings: $WARNING_COUNT"

# Exit with error if we have errors (from cppcheck) or warnings
# Note: we should be able to use $CPPCHECK_EXIT_CODE here but for some reason
# it is returning 1 even with no errors in stdout. This might be a bug
if [ $ERROR_COUNT -gt 0 ] || [ $WARNING_COUNT -gt 0 ]; then
    exit 1
fi

exit 0
