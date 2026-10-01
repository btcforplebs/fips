#!/bin/bash
# ── Surface tests that passed only on retry ─────────────────────────────────
# The ci nextest profile (.config/nextest.toml) retries a failing test twice,
# so a test that fails and then passes reports green. nextest says so only in
# its summary count ("N passed (1 flaky)") and a FLAKY line in the job log,
# where nobody looks on a green run; that is how a real race in a test went
# unnoticed until someone happened to read the output. The profile's own
# comment names the remedy: surface retried-but-passed tests, and keep the
# retries so a flake does not red an unrelated run.
#
# This reads the profile's JUnit report and, for every test case carrying a
# <flakyFailure> (an attempt that failed before the final one passed), emits a
# GitHub warning annotation and a line in the step summary. A test that failed
# every attempt carries <failure> instead and is the nextest step's red, not
# this script's concern.
#
# The report is parsed with awk rather than an XML library so the script runs
# unchanged on the Linux, macOS and Windows (Git Bash) runners. It relies on
# quick-junit's layout, one element per line, and on the two element names
# appearing only as elements: in text and attributes `<` is always escaped.
#
# Usage: check-nextest-flaky.sh [junit.xml]
#   Default path: target/nextest/ci/junit.xml, the ci profile's report.
# Exit 0 = the report was read (flaky tests, if any, were annotated; they do
# not fail the step). Exit 2 = no report, or one with no test cases: nothing
# was checked, and that is never reported as a pass.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

REPORT="${1:-target/nextest/ci/junit.xml}"

if [[ ! -s "$REPORT" ]]; then
    echo "::error title=Flaky-test check::no JUnit report at $REPORT; flaky tests were not checked"
    exit 2
fi

# One line per flaky test: "<failed attempts><TAB><classname><TAB><name>",
# then a final "cases<TAB><count>" line so an empty or truncated report is
# told apart from a clean one.
if ! parsed="$(awk '
    function attr(line, key,    m, v) {
        if (match(line, " " key "=\"[^\"]*\"")) {
            v = substr(line, RSTART + length(key) + 3, RLENGTH - length(key) - 4)
            gsub(/&lt;/, "<", v); gsub(/&gt;/, ">", v); gsub(/&quot;/, "\"", v)
            gsub(/&apos;/, "\047", v); gsub(/&amp;/, "\\&", v)
            return v
        }
        return ""
    }
    function flush() {
        if (fails > 0) printf "%d\t%s\t%s\n", fails, cls, name
        fails = 0
    }
    /<testcase[ >]/ { flush(); cases++; name = attr($0, "name"); cls = attr($0, "classname") }
    /<flakyFailure[ >]/ { fails++ }
    END { flush(); printf "cases\t%d\n", cases }
' "$REPORT")"; then
    echo "::error title=Flaky-test check::could not parse $REPORT; flaky tests were not checked"
    exit 2
fi

cases="$(printf '%s\n' "$parsed" | awk -F'\t' '$1 == "cases" { print $2 }')"
if [[ -z "$cases" || "$cases" -eq 0 ]]; then
    echo "::error title=Flaky-test check::$REPORT lists no test cases; flaky tests were not checked"
    exit 2
fi

flaky=0
summary=""
while IFS=$'\t' read -r fails cls name; do
    [[ "$fails" == "cases" ]] && continue
    flaky=$((flaky + 1))
    # Workflow-command values escape %, CR and LF; names carry none of the
    # latter, but a % in a test name would otherwise be read as an escape.
    msg="$cls $name failed $fails attempt(s) before passing on retry"
    echo "::warning title=Flaky test::${msg//%/%25}"
    summary+="- \`$cls $name\`: failed $fails attempt(s), then passed"$'\n'
done <<< "$parsed"

if [[ "$flaky" -eq 0 ]]; then
    echo "check-nextest-flaky: $cases test case(s), none passed only on retry"
    exit 0
fi

echo "check-nextest-flaky: $flaky of $cases test case(s) passed only on retry"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
        echo "### Flaky tests ($flaky)"
        echo ""
        echo "These failed at least once and passed on a retry, so the run is green."
        echo ""
        printf '%s' "$summary"
    } >> "$GITHUB_STEP_SUMMARY"
fi
exit 0
