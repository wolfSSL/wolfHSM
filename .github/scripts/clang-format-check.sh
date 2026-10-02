#!/bin/sh
#
# Rejects changed lines that are not clang-format clean. Shared by the
# pre-commit hook and by CI so both judge identically.
#
#   clang-format-check.sh              staged changes (pre-commit)
#   clang-format-check.sh <base-ref>   changes since <base-ref> (CI)
#
# Only the changed lines are checked, so this does not demand a reformat
# of surrounding code that predates the style file.
#
# git-clang-format spawns a separate clang-format, defaulting to the
# unversioned one on PATH, so the wrapper and the binary are both pinned
# here. A mismatched pair fails outright.
#
# Bypass:
#   git commit -n                 skips every hook
#   SKIP_CLANG_FORMAT=1 git ...   skips just this check
#

[ -n "$SKIP_CLANG_FORMAT" ] && exit 0

ver=${CLANG_FORMAT_VERSION:-18}
bin="clang-format-$ver"
wrapper="git-clang-format-$ver"

top=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
[ -f "$top/.clang-format" ] || exit 0

# Skipping keeps a missing formatter from blocking commits. CI asserts the
# binaries are present in a separate step, so it cannot skip silently.
if ! command -v "$wrapper" >/dev/null 2>&1; then
    echo "clang-format: $wrapper not found, skipping" >&2
    exit 0
fi

# git-clang-format needs a commit to diff against, so the very first
# commit in a repo cannot be checked.
git rev-parse --verify --quiet HEAD >/dev/null || exit 0

if [ -n "$1" ]; then
    scope=$1
else
    scope=--staged
fi

out=$("$wrapper" --binary "$bin" --diff -q "$scope" 2>&1)
ret=$?

if [ $ret -eq 0 ]; then
    exit 0
fi

if [ $ret -ne 1 ]; then
    echo "$out" >&2
    echo "clang-format: $wrapper failed (exit $ret)" >&2
    exit $ret
fi

echo "$out"
echo ""
echo "ERROR: changed lines are not clang-format clean."
echo ""
# Not "&& git add -u": the wrapper exits 1 when it reformats something.
echo "Fix with:"
echo "    $wrapper --binary $bin $scope; git add -u"
echo ""
echo "Or bypass with:"
echo "    SKIP_CLANG_FORMAT=1 git commit ..."
exit 1
