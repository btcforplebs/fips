#!/bin/bash
# Tests for ci-local.sh's argument handling: an unknown option or an option
# missing its value is a usage error (exit 2, message on stderr), and --help
# still exits 0 with the usage on stdout.
#
# Every case invokes ci-local.sh with arguments that end during parsing, before
# the load sampler, traps, containers or any build, so the suite is hermetic and
# takes about a second. Each invocation is bounded by a timeout, so a parse that
# fell through into a real run fails the case instead of starting one.
#
# Run:
#   ./ci-args-test.sh
# Exits 0 only if every case passes; non-zero if any case fails.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CI_LOCAL="$SCRIPT_DIR/../ci-local.sh"

FAILURES=0
OUT_FILE="$(mktemp)"
ERR_FILE="$(mktemp)"
trap 'rm -f "$OUT_FILE" "$ERR_FILE"' EXIT

# Record a single assertion result.
check() {
    local name="$1"
    local ok="$2"      # 0 = pass, anything else = fail
    local detail="${3:-}"
    if [ "$ok" -eq 0 ]; then
        echo "PASS  $name${detail:+  ($detail)}"
    else
        echo "FAIL  $name${detail:+  ($detail)}"
        FAILURES=$((FAILURES + 1))
    fi
    return 0
}

# Run ci-local.sh with the given arguments; sets RC, OUT and ERR.
invoke() {
    RC=0
    timeout 30 bash "$CI_LOCAL" "$@" >"$OUT_FILE" 2>"$ERR_FILE" || RC=$?
    OUT="$(cat "$OUT_FILE")"
    ERR="$(cat "$ERR_FILE")"
    return 0
}

# Assert exit status 2 and that stderr carries the expected text.
expect_usage_error() {
    local name="$1" text="$2"
    shift 2
    invoke "$@"
    check "$name: exits 2" "$([ "$RC" -eq 2 ] && echo 0 || echo 1)" "rc=$RC"
    check "$name: stderr names the problem" \
        "$(grep -qF -- "$text" <<<"$ERR" && echo 0 || echo 1)" "want '$text'"
    return 0
}

# Assert exit status 0 and the usage text on stdout.
expect_help() {
    local name="$1"
    shift
    invoke "$@"
    check "$name: exits 0" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)" "rc=$RC"
    check "$name: usage on stdout" \
        "$(grep -qF -- "Usage: ./ci-local.sh" <<<"$OUT" && echo 0 || echo 1)"
    return 0
}

expect_usage_error "unknown option" "Unknown option: --no-such-option" \
    --no-such-option
expect_help "--help" --help
expect_help "-h" -h
expect_usage_error "--only without a value" "--only needs a value" --only
expect_usage_error "--jobs without a value" "--jobs needs a value" --jobs
expect_usage_error "-j without a value" "-j needs a value" -j

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "All ci-local.sh argument cases passed"
    exit 0
fi
echo "$FAILURES ci-local.sh argument check(s) failed"
exit 1
