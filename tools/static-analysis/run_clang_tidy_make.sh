#!/bin/bash

# wolfHSM clang-tidy static analysis runner
# Uses wolfSSL's proven clang-tidy configuration for consistent code quality

set -o noclobber -o nounset -o pipefail || exit $?

# Script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit $?
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)" || exit $?

# Output directory
OUTPUT_DIR="$SCRIPT_DIR/reports"
mkdir -p "$OUTPUT_DIR" || exit $?

# Check if clang-tidy is installed
if ! command -v clang-tidy &> /dev/null; then
    echo "Error: clang-tidy is not installed or not in PATH" >&2
    exit 1
fi

echo "Using clang-tidy version: $(clang-tidy --version | head -n 1)"

# Check if clang is installed
if ! command -v clang &> /dev/null; then
    echo "Error: clang is not installed or not in PATH" >&2
    exit 1
fi

# Set up environment variables for clang/clang-tidy binaries
export CLANG_TIDY="$(command -v clang-tidy)"
export CLANG="$(command -v clang)"

# wolfHSM clang-tidy configuration using wolfSSL's exact configuration
# Using portable variable checking for compatibility with older bash versions
if [[ -z "${CLANG_TIDY_ARGS+x}" ]]; then
    export CLANG_TIDY_ARGS='-allow-enabling-analyzer-alpha-checkers -header-filter=^(?!.*wolfssl).* -checks=readability-*,bugprone-*,misc-no-recursion,misc-misplaced-const,misc-redundant-expression,misc-unused-parameters,misc-unused-using-decls,-clang-diagnostic-language-extension-token,-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling,-clang-analyzer-optin.performance.Padding,-readability-braces-around-statements,-readability-function-size,-readability-function-cognitive-complexity,-bugprone-suspicious-include,-bugprone-easily-swappable-parameters,-readability-isolate-declaration,-readability-magic-numbers,-readability-else-after-return,-bugprone-reserved-identifier,-readability-suspicious-call-argument,-bugprone-suspicious-string-compare,-bugprone-branch-clone,-misc-redundant-expression,-readability-non-const-parameter,-readability-redundant-control-flow,-readability-misleading-indentation,-readability-identifier-length,-readability-duplicate-include,-readability-avoid-const-params-in-decls,-readability-avoid-unconditional-preprocessor-if,-readability-use-concise-preprocessor-directives,-bugprone-narrowing-conversions,-bugprone-implicit-widening-of-multiplication-result,-bugprone-assignment-in-if-condition,-clang-analyzer-alpha*,-bugprone-switch-missing-default-case,-bugprone-multi-level-implicit-pointer-conversion,-bugprone-casting-through-void,-readability-avoid-nested-conditional-operator,-readability-redundant-casting,-readability-enum-initial-value,-readability-math-missing-parentheses,-clang-analyzer-security.ArrayBound,-clang-analyzer-osx.SecKeychainAPI'
fi

if [[ -z "${CLANG_TIDY_PER_FILE_CHECKS+x}" ]]; then
    export CLANG_TIDY_PER_FILE_CHECKS='^(src|benchmark|examples|port|test|wolfhsm|tools)/:concurrency-mt-unsafe ^examples/:-clang-analyzer-unix.Stream,-clang-analyzer-unix.StdCLibraryFunctions ^test/.*\.c:-clang-analyzer-unix.StdCLibraryFunctions ^src/.*_(arm|c|dsp|x86).*\.c:-readability-redundant-preprocessor,-bugprone-signed-char-misuse'
fi

if [[ -z "${CLANG_TIDY_CONFIG+x}" ]]; then
    export CLANG_TIDY_CONFIG='{CheckOptions: [{key: concurrency-mt-unsafe.FunctionSet, value: glibc}, {key: bugprone-unused-return-value.AllowCastToVoid, value: true}, {key: bugprone-unused-return-value.CheckedFunctions, value: pthread_cond_wait;pthread_attr_destroy;pthread_attr_init;pthread_attr_setdetachstate;pthread_attr_setinheritsched;pthread_attr_setschedparam;pthread_attr_setschedpolicy;pthread_attr_setscope;pthread_attr_setstack;pthread_cancel;pthread_cond_destroy;pthread_cond_init;pthread_cond_signal;pthread_cond_wait;pthread_create;pthread_detach;pthread_getschedparam;pthread_getspecific;pthread_join;pthread_key_create;pthread_mach_thread_np;pthread_mutex_destroy;pthread_mutex_init;pthread_mutex_lock;pthread_mutex_unlock;pthread_setaffinity_np;pthread_setschedparam;pthread_setspecific;snprintf;vsnprintf;gettimeofday;clock_gettime;bind;closedir;connect;fcntl;fgets;fputc;fread;fseek;fwrite;getaddrinfo;getpeername;gmtime_r;inet_pton;inotify_rm_watch;listen;^read$;realloc;recvfrom;recv;select;send;sendto;setsockopt;^stat$;^write$}, {key: bugprone-sizeof-expression.WarnOnOffsetDividedBySizeOf, value: false} ]}'
fi

# Additional configuration variables - match wolfSSL pattern
if [[ -z "${CLANG_TIDY_PER_FILE_ARGS+x}" ]]; then
    export CLANG_TIDY_PER_FILE_ARGS=""
fi

if [[ -z "${CLANG_TIDY_EXTRA_ARGS+x}" ]]; then
    export CLANG_TIDY_EXTRA_ARGS=""
fi

if [[ -z "${CLANG_TIDY_STATUS_FILE+x}" ]]; then
    export CLANG_TIDY_STATUS_FILE="$OUTPUT_DIR/clang_tidy_status.txt"
    > "$CLANG_TIDY_STATUS_FILE"
fi

if [[ -z "${WOLFSSL_CLANG_TIDY+x}" ]]; then
    export WOLFSSL_CLANG_TIDY=1
fi

# CLANG_OVERRIDE_CFLAGS can be used to pass additional flags to clang
if [[ -z "${CLANG_OVERRIDE_CFLAGS+x}" ]]; then
    export CLANG_OVERRIDE_CFLAGS=""
fi

# Run clang-tidy analysis on wolfHSM source code

# Clear output files
> "$OUTPUT_DIR/clang_tidy_output.txt" || exit $?
> "$OUTPUT_DIR/clang_tidy_summary.txt" || exit $?

echo "Running comprehensive clang-tidy analysis on all wolfHSM directories..."
echo "Analyzing: src/, test/, benchmark/, examples/, port/, tools/, wolfhsm/"
echo "Excluding: wolfssl/, .github/"
echo ""

# Change to project root
cd "$PROJECT_ROOT" || exit $?

# Set up the build environment
export CC="$SCRIPT_DIR/clang-tidy-builder.sh"
export WOLFSSL_DIR="$PROJECT_ROOT/wolfssl"
export USER_SETTINGS_DIR="$PROJECT_ROOT/test/config"

# Function to run make and capture output
function run_make_target() {
    local target_dir="$1"
    local target_name="$2"

    echo "=== Building $target_name in $target_dir ==="

    if [[ ! -d "$target_dir" ]]; then
        echo "Directory $target_dir does not exist, skipping..."
        return 0
    fi

    if [[ ! -f "$target_dir/Makefile" ]]; then
        echo "No Makefile in $target_dir, skipping..."
        return 0
    fi

    # Clean the build first
    make -C "$target_dir" clean > /dev/null 2>&1 || true

    # Run make and append output
    if make -C "$target_dir" 2>&1 | tee -a "$OUTPUT_DIR/clang_tidy_output.txt"; then
        return 0
    else
        return ${PIPESTATUS[0]}
    fi
}

# Run builds for all wolfHSM components
overall_result=0

# Build test suite (includes src/ and port/)
if ! run_make_target "test" "wolfHSM test suite"; then
    overall_result=2
fi

# Build benchmark suite
if ! run_make_target "benchmark" "wolfHSM benchmarks"; then
    overall_result=2
fi

# Build examples
if ! run_make_target "examples" "wolfHSM examples"; then
    overall_result=2
fi

# Build tools
if ! run_make_target "tools" "wolfHSM tools"; then
    overall_result=2
fi

BUILD_RESULT=$overall_result

# Check if status file has any errors
if [[ -s "$CLANG_TIDY_STATUS_FILE" ]]; then
    echo ""
    echo "clang-tidy reported errors in the following files:"
    cat "$CLANG_TIDY_STATUS_FILE"
    TIDY_ERRORS=1
else
    TIDY_ERRORS=0
fi

# Process the output to create a summary
echo ""
echo "Processing results..."

# Extract errors and warnings (excluding notes)
rm -f "$OUTPUT_DIR/clang_tidy_summary.txt"
grep -E "^[^:]+\.(c|h):[0-9]+:[0-9]+: (error|warning):" "$OUTPUT_DIR/clang_tidy_output.txt" > "$OUTPUT_DIR/clang_tidy_summary.txt" 2>/dev/null || true

# Count issues
ERROR_COUNT=$(grep -c " error:" "$OUTPUT_DIR/clang_tidy_summary.txt" 2>/dev/null) || ERROR_COUNT=0
WARNING_COUNT=$(grep -c " warning:" "$OUTPUT_DIR/clang_tidy_summary.txt" 2>/dev/null) || WARNING_COUNT=0
TOTAL_ISSUES=$((ERROR_COUNT + WARNING_COUNT))

echo ""
echo "Static analysis complete!"
echo "Full output: $OUTPUT_DIR/clang_tidy_output.txt"
echo "Summary: $OUTPUT_DIR/clang_tidy_summary.txt"
if [[ -s "$CLANG_TIDY_STATUS_FILE" ]]; then
    echo "Status file: $CLANG_TIDY_STATUS_FILE"
fi
echo ""
echo "Results:"
echo "  Errors: $ERROR_COUNT"
echo "  Warnings: $WARNING_COUNT"
echo "  Total issues: $TOTAL_ISSUES"

# Exit with appropriate code
if [[ $BUILD_RESULT -ne 0 ]]; then
    echo ""
    echo "❌ clang-tidy build/analysis failed (make exit: $BUILD_RESULT)"
    exit $BUILD_RESULT
elif [[ $TIDY_ERRORS -ne 0 ]]; then
    echo ""
    echo "❌ clang-tidy found errors that must be fixed (see status file)"
    exit 1
elif [[ $ERROR_COUNT -gt 0 ]]; then
    echo ""
    echo "❌ clang-tidy found $ERROR_COUNT error(s) that must be fixed"
    exit 1
elif [[ $WARNING_COUNT -gt 0 ]]; then
    echo ""
    echo "⚠️ clang-tidy found $WARNING_COUNT warning(s) - consider fixing these"
    exit 0  # Exit success for now, can change to exit 1 to enforce warnings
else
    echo ""
    echo "✅ clang-tidy analysis passed - no issues found"
    exit 0
fi
