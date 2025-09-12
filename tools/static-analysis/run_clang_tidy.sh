#!/bin/bash

# Simple clang-tidy script for wolfHSM static analysis

# Don't exit on error immediately since we want to handle clang-tidy exit codes
set +e

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Output directory
OUTPUT_DIR="$SCRIPT_DIR/reports"
mkdir -p "$OUTPUT_DIR"

# Function to check if clang-tidy is installed
check_clang_tidy() {
    if ! command -v clang-tidy &> /dev/null; then
        echo "Error: clang-tidy is not installed or not in PATH"
        return 1
    fi
    echo "Using clang-tidy version: $(clang-tidy --version | head -n 1)"
    return 0
}

# Function to generate compile_commands.json if it doesn't exist
generate_compile_commands() {
    if [ ! -f "$PROJECT_ROOT/compile_commands.json" ]; then
        echo "No compile_commands.json found. Generating one..."
        
        # Change to project root
        cd "$PROJECT_ROOT"
        
        # Try to generate using bear if available
        if command -v bear &> /dev/null; then
            echo "Using bear to generate compile_commands.json..."
            make clean > /dev/null 2>&1 || true
            bear -- make WOLFSSL_DIR="$PROJECT_ROOT/wolfssl"
        else
            echo "Warning: bear is not installed. Creating a basic compile_commands.json..."
            # Create a basic compile_commands.json for all .c files
            echo "[" > compile_commands.json
            first=true
            find src wolfhsm -name "*.c" | while read -r file; do
                if [ "$first" = true ]; then
                    first=false
                else
                    echo "," >> compile_commands.json
                fi
                cat >> compile_commands.json << EOF
  {
    "directory": "$PROJECT_ROOT",
    "command": "gcc -std=c99 -Wall -I$PROJECT_ROOT/wolfhsm -I$PROJECT_ROOT/src -I$PROJECT_ROOT/wolfssl -c $file",
    "file": "$file"
  }
EOF
            done
            echo "]" >> compile_commands.json
        fi
        
        # Return to script directory
        cd "$SCRIPT_DIR"
    else
        echo "Using existing compile_commands.json"
    fi
}

# Check if clang-tidy is installed
if ! check_clang_tidy; then
    exit 1
fi

# Generate or use existing compile_commands.json
generate_compile_commands

# Copy the .clang-tidy config to project root if it doesn't exist
if [ -f "$SCRIPT_DIR/.clang-tidy" ] && [ ! -f "$PROJECT_ROOT/.clang-tidy" ]; then
    cp "$SCRIPT_DIR/.clang-tidy" "$PROJECT_ROOT/.clang-tidy"
fi

echo "Running clang-tidy static analysis on wolfHSM..."

# Find all source files
SOURCE_FILES=$(find "$PROJECT_ROOT/src" "$PROJECT_ROOT/wolfhsm" -name "*.c" -o -name "*.h" | grep -v "/Build/" | sort)

# Run clang-tidy and capture output
CLANG_TIDY_OUTPUT="$OUTPUT_DIR/clang_tidy_output.txt"
CLANG_TIDY_SUMMARY="$OUTPUT_DIR/clang_tidy_summary.txt"

# Clear previous outputs
> "$CLANG_TIDY_OUTPUT"
> "$CLANG_TIDY_SUMMARY"

# Run clang-tidy on all files
echo "Analyzing $(echo "$SOURCE_FILES" | wc -l) files..."
TOTAL_ISSUES=0
ERROR_COUNT=0
WARNING_COUNT=0
NOTE_COUNT=0

for file in $SOURCE_FILES; do
    echo -n "Analyzing $file... "
    
    # Run clang-tidy on the file
    output=$(clang-tidy "$file" -p "$PROJECT_ROOT" 2>&1)
    
    # Check if there were any issues
    if echo "$output" | grep -q "warning:\|error:\|note:"; then
        echo "found issues"
        echo "=== $file ===" >> "$CLANG_TIDY_OUTPUT"
        echo "$output" >> "$CLANG_TIDY_OUTPUT"
        echo "" >> "$CLANG_TIDY_OUTPUT"
        
        # Count issues
        file_errors=$(echo "$output" | grep -c "error:" || true)
        file_warnings=$(echo "$output" | grep -c "warning:" || true)
        file_notes=$(echo "$output" | grep -c "note:" || true)
        
        ERROR_COUNT=$((ERROR_COUNT + file_errors))
        WARNING_COUNT=$((WARNING_COUNT + file_warnings))
        NOTE_COUNT=$((NOTE_COUNT + file_notes))
        
        # Add to summary (excluding notes)
        echo "$output" | grep -E "(error:|warning:)" | while IFS= read -r line; do
            echo "$file: $line" >> "$CLANG_TIDY_SUMMARY"
        done
    else
        echo "clean"
    fi
done

TOTAL_ISSUES=$((ERROR_COUNT + WARNING_COUNT))

echo ""
echo "Static analysis complete!"
echo "Full output: $CLANG_TIDY_OUTPUT"
echo "Summary: $CLANG_TIDY_SUMMARY"
echo ""
echo "Results:"
echo "  Errors: $ERROR_COUNT"
echo "  Warnings: $WARNING_COUNT"
echo "  Notes: $NOTE_COUNT (informational only)"
echo "  Total issues: $TOTAL_ISSUES"

# Exit with error if we have errors or warnings
if [ $TOTAL_ISSUES -gt 0 ]; then
    echo ""
    echo "❌ clang-tidy found $TOTAL_ISSUES issue(s) that need to be addressed"
    exit 1
else
    echo ""
    echo "✅ clang-tidy analysis passed - no issues found"
    exit 0
fi