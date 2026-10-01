#!/bin/bash
# ── Fixture tests for check-nextest-flaky.sh ────────────────────────────────
# The checker only runs on GitHub, after the ci-profile nextest steps, and a
# flaky test there is rare: a checker that stopped seeing them would stay quiet
# for months and look exactly like a healthy one. These fixtures pin its
# behaviour instead. Each is a real JUnit report from cargo-nextest 0.9.146
# under this repository's ci profile (retries = 2), run over a four-test crate:
#
#   clean.xml   every test passed on its first attempt
#   flaky.xml   two tests failed once and passed on retry (FLAKY 2/3)
#   failed.xml  one test failed all three attempts (<failure>, <rerunFailure>)
#
# The flaky fixture must produce one warning per flaky test and a step-summary
# entry for each; the clean and failed fixtures must produce none, since a test
# that never passed is the nextest step's red, not a flake. A missing report
# must not read as clean.
#
# Exit 0 = every case behaved. Exit 1 = a case did not.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHECK="$SCRIPT_DIR/../check-nextest-flaky.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FAILED=0
ok()  { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; FAILED=$((FAILED + 1)); }

# expect <description of a pass> <description of a failure> <command...>:
# records ok when the command succeeds and a failure otherwise.
expect() {
    local good="$1" poor="$2"
    shift 2
    if "$@"; then ok "$good"; else bad "$poor"; fi
    return 0
}

# run_case <fixture path>: runs the checker with a fresh step summary, leaving
# its output in $WORK/out, the summary in $WORK/summary and its status in RC.
run_case() {
    : > "$WORK/summary"
    GITHUB_STEP_SUMMARY="$WORK/summary" bash "$CHECK" "$1" > "$WORK/out" 2>&1
    RC=$?
    WARNINGS="$(grep -c '^::warning title=Flaky test::' "$WORK/out")"
    return 0
}

echo "check-nextest-flaky fixtures"

run_case "$SCRIPT_DIR/flaky.xml"
expect "flaky: exit 0, so a flake does not red the run" "flaky: exit $RC, expected 0" \
    test "$RC" -eq 0
expect "flaky: one warning per flaky test" "flaky: $WARNINGS warning(s), expected 2" \
    test "$WARNINGS" -eq 2
for t in tests::flips_once tests::also_flips; do
    if grep -q "^::warning title=Flaky test::flakydemo $t failed 1 attempt(s)" "$WORK/out" \
        && grep -q "flakydemo $t\`: failed 1 attempt(s)" "$WORK/summary"; then
        ok "flaky: $t named in a warning and in the step summary"
    else
        bad "flaky: $t missing from the warnings or the step summary"
    fi
done
if grep -q 'tests::steady\|tests::always_fails' "$WORK/out" "$WORK/summary"; then
    bad "flaky: a test that passed first time was reported"
else
    ok "flaky: tests that passed first time are not reported"
fi

run_case "$SCRIPT_DIR/clean.xml"
expect "clean: exit 0, no warning, no summary" \
    "clean: exit $RC, $WARNINGS warning(s), summary $(wc -c < "$WORK/summary") bytes" \
    test "$RC" -eq 0 -a "$WARNINGS" -eq 0 -a ! -s "$WORK/summary"
expect "clean: all four cases were read" "clean: did not report reading four cases" \
    grep -q '4 test case(s), none passed only on retry' "$WORK/out"

run_case "$SCRIPT_DIR/failed.xml"
expect "failed: a test that never passed is not reported as flaky" \
    "failed: exit $RC, $WARNINGS warning(s)" \
    test "$RC" -eq 0 -a "$WARNINGS" -eq 0

run_case "$WORK/no-such-report.xml"
expect "missing report: exit 2, not a clean pass" "missing report: exit $RC, expected 2" \
    test "$RC" -eq 2 -a "$WARNINGS" -eq 0

echo '<?xml version="1.0" encoding="UTF-8"?><testsuites name="nextest-run" tests="0"/>' > "$WORK/empty.xml"
run_case "$WORK/empty.xml"
expect "report with no test cases: exit 2, not a clean pass" \
    "report with no test cases: exit $RC, expected 2" \
    test "$RC" -eq 2

if [[ "$FAILED" -ne 0 ]]; then
    echo "check-nextest-flaky fixtures: $FAILED case(s) failed"
    exit 1
fi
echo "check-nextest-flaky fixtures: all cases passed"
exit 0
