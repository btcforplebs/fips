#!/bin/bash
# Unit tests for relay_lab_start() and relay_start_gate() in relay-verdict.sh,
# and for assert_relay() still failing a run whose relay restarted after a
# clean start.
#
# `docker` and `sleep` are replaced with shell functions. The docker stand-in
# answers `inspect` and `logs` from a scripted relay whose state depends on the
# start attempt and on how many polls the gate has made, and the sleep
# stand-in counts those polls instead of waiting. The start and stop functions
# handed to relay_lab_start are counting stand-ins. No containers or network
# are involved, so the suite is hermetic and takes about a second.
#
# Run:
#   ./relay-verdict-test.sh
# Exits 0 only if every case passes; non-zero if any case fails.

# The stand-ins below are called only through the library and through the
# scene name held in SCENE, which shellcheck cannot follow.
# shellcheck disable=SC2317

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=relay-verdict.sh
source "$SCRIPT_DIR/relay-verdict.sh"

RESULTS=()
FAILURES=0

# Record a single assertion result.
check() {
    local name="$1"
    local ok="$2"      # 0 = pass, anything else = fail
    local detail="${3:-}"
    if [ "$ok" -eq 0 ]; then
        RESULTS+=("PASS  $name")
        echo "PASS  $name${detail:+  ($detail)}"
    else
        RESULTS+=("FAIL  $name")
        echo "FAIL  $name${detail:+  ($detail)}"
        FAILURES=$((FAILURES + 1))
    fi
    return 0
}

# --- The scripted relay -------------------------------------------------

RELAY="fips-nat-relay-test"
ATTEMPT=0     # how many times the lab was started
POLL=0        # gate polls since the last start
STARTS=0
STOPS=0
START_RC=0    # what the start stand-in returns
STOP_RC=0     # what the stop stand-in returns
SCENE=""      # name of the scene function that describes the relay

CONNECT_1="[Websocket       ]INFO| [1] Connect from 10.41.1.50 compression=N sliding=N"
CONNECT_2="[Websocket       ]INFO| [2] Connect from 10.41.1.51 compression=N sliding=N"
STARTED="[Websocket       ]INFO| Started websocket server on 0.0.0.0:7777"
SEGV="Loguru caught a signal: SIGSEGV"
PHMAP="Assertion failed: i < capacity_ (golpe/external/parallel-hashmap/parallel_hashmap/phmap.h: set_ctrl: 2253)"
ABRT="Loguru caught a signal: SIGABRT"

# A scene sets these from ATTEMPT and POLL.
STATUS=""; EXITC=0; RESTARTS=0; LOG=""; INSPECT_FAIL=0; LOGS_FAIL=0

set_relay() {
    STATUS="$1"; EXITC="$2"; RESTARTS="$3"; LOG="$4"
    INSPECT_FAIL=0; LOGS_FAIL=0
    return 0
}

clean_log() {
    printf '%s\n%s\n%s' "$STARTED" "$CONNECT_1" "$CONNECT_2"
    return 0
}

# Two connects, then a segfault and a restart one poll later.
scene_segv_once() {
    if [ "$ATTEMPT" -eq 1 ] && [ "$POLL" -ge 1 ]; then
        set_relay running 0 1 "$(clean_log)"$'\n'"$SEGV"$'\n'"$STARTED"
    else
        set_relay running 0 0 "$(clean_log)"
    fi
    return 0
}

# The same, with the phmap assertion and its SIGABRT.
scene_phmap_once() {
    if [ "$ATTEMPT" -eq 1 ] && [ "$POLL" -ge 1 ]; then
        set_relay running 0 1 \
            "$(clean_log)"$'\n'"$PHMAP"$'\n'"$ABRT"$'\n'"$STARTED"
    else
        set_relay running 0 0 "$(clean_log)"
    fi
    return 0
}

# Faults one poll after the connects on every start.
scene_segv_always() {
    if [ "$POLL" -ge 1 ]; then
        set_relay running 0 1 "$(clean_log)"$'\n'"$SEGV"$'\n'"$STARTED"
    else
        set_relay running 0 0 "$(clean_log)"
    fi
    return 0
}

scene_clean() {
    set_relay running 0 0 "$(clean_log)"
    return 0
}

# Exits before any client connects on the first start.
scene_exit_early() {
    if [ "$ATTEMPT" -eq 1 ]; then
        set_relay exited 139 0 "$STARTED"$'\n'"$SEGV"
    else
        set_relay running 0 0 "$(clean_log)"
    fi
    return 0
}

# Only one client ever connects.
scene_one_client() {
    set_relay running 0 0 "$STARTED"$'\n'"$CONNECT_1"
    return 0
}

scene_inspect_fails() {
    set_relay running 0 0 ""
    INSPECT_FAIL=1
    return 0
}

scene_logs_fail() {
    set_relay running 0 0 ""
    LOGS_FAIL=1
    return 0
}

# A clean start, then a restart in the middle of the run: with a fault line
# (MIDRUN=1), or with none, as a relay killed from outside leaves (MIDRUN=2).
scene_midrun_restart() {
    if [ "$MIDRUN" -eq 1 ]; then
        set_relay running 0 1 "$(clean_log)"$'\n'"$SEGV"$'\n'"$STARTED"
    elif [ "$MIDRUN" -eq 2 ]; then
        set_relay running 0 1 "$(clean_log)"$'\n'"$STARTED"
    else
        set_relay running 0 0 "$(clean_log)"
    fi
    return 0
}
MIDRUN=0

# The docker stand-in. Runs inside the callers' command substitutions, so it
# only reads the counters; the start and sleep stand-ins advance them.
docker() {
    "$SCENE"
    case "$1" in
        inspect)
            [ "$INSPECT_FAIL" -eq 1 ] && return 1
            case "$3" in
                *ExitCode*) echo "$STATUS $EXITC $RESTARTS" ;;
                *) echo "$STATUS $RESTARTS" ;;
            esac
            return 0
            ;;
        logs)
            [ "$LOGS_FAIL" -eq 1 ] && { echo "Error: cannot read logs"; return 1; }
            printf '%s\n' "$LOG"
            return 0
            ;;
    esac
    return 1
}

sleep() {
    POLL=$((POLL + 1))
    return 0
}

start_lab() {
    STARTS=$((STARTS + 1))
    ATTEMPT=$((ATTEMPT + 1))
    POLL=0
    return "$START_RC"
}

stop_lab() {
    STOPS=$((STOPS + 1))
    return "$STOP_RC"
}

OUT=$(mktemp)
trap 'rm -f "$OUT"' EXIT

# Run relay_lab_start in this shell, so the counters survive, with the given
# scene, gate timeout, and start and stop return codes. Leaves its rc in RC
# and its output in $OUT.
RC=0
run_start() {
    local scene="$1" timeout="${2:-45}"
    SCENE="$scene"; ATTEMPT=0; POLL=0; STARTS=0; STOPS=0
    START_RC="${3:-0}"; STOP_RC="${4:-0}"; MIDRUN=0
    RC=0
    relay_lab_start "$RELAY" 2 "$timeout" start_lab stop_lab >"$OUT" 2>&1 || RC=$?
    cat "$OUT"
    return 0
}

has() {
    grep -qF -- "$1" "$OUT"
    return $?
}

# Assert rc, start and stop counts.
expect() {
    local tag="$1" rc="$2" starts="$3" stops="$4" ok
    ok=1; [ "$RC" -eq "$rc" ] && ok=0
    check "$tag: returns $rc" "$ok" "rc=$RC"
    ok=1; [ "$STARTS" -eq "$starts" ] && ok=0
    check "$tag: lab started $starts time(s)" "$ok" "starts=$STARTS"
    ok=1; [ "$STOPS" -eq "$stops" ] && ok=0
    check "$tag: lab stopped $stops time(s)" "$ok" "stops=$STOPS"
    return 0
}

expect_has() {
    local tag="$1" text="$2" ok=1
    has "$text" && ok=0
    check "$tag: output has '$text'" "$ok"
    return 0
}

expect_lacks() {
    local tag="$1" text="$2" ok=0
    has "$text" && ok=1
    check "$tag: output lacks '$text'" "$ok"
    return 0
}

M1="RELAY START FAULT (attempt 1 of 2)"
M2="RELAY START FAULT (attempt 2 of 2)"
LOGBEGIN="--- $RELAY: full log begin ---"

echo
echo "== Case 1: segfault at the first connects, then a clean start =="
run_start scene_segv_once
expect case1 0 2 1
expect_has case1 "$M1"
expect_has case1 "$LOGBEGIN"
expect_has case1 "$SEGV"
expect_lacks case1 "$M2"

echo
echo "== Case 2: phmap abort at the first connects, then a clean start =="
run_start scene_phmap_once
expect case2 0 2 1
expect_has case2 "$M1"
expect_has case2 "$LOGBEGIN"
expect_has case2 "$PHMAP"

echo
echo "== Case 3: the relay faults on both starts =="
run_start scene_segv_always
expect case3 1 2 1
expect_has case3 "$M1"
expect_has case3 "$M2"

echo
echo "== Case 4: clean start =="
run_start scene_clean
expect case4 0 1 0
expect_lacks case4 "RELAY START FAULT"
expect_has case4 "with no fault in its start window"
c4_settle=1; [ "$POLL" -ge 4 ] && c4_settle=0
check "case4: the window stayed open for the settle polls" "$c4_settle" "polls=$POLL"

echo
echo "== Case 5: the relay exits before any client connects =="
run_start scene_exit_early
expect case5 0 2 1
expect_has case5 "$M1"
expect_has case5 "is exited"

echo
echo "== Case 6: the clients never all connect =="
run_start scene_one_client 2
expect case6 0 1 0
expect_has case6 "start window not established"
expect_lacks case6 "RELAY START FAULT"

echo
echo "== Case 7: the relay's state cannot be read =="
run_start scene_inspect_fails
expect case7 1 2 1
expect_has case7 "$M1"
expect_has case7 "$M2"
expect_has case7 "state could not be read"

echo "-- Case 7b: the relay's log cannot be read --"
run_start scene_logs_fail
expect case7b 1 2 1
expect_has case7b "log that could not be read"

echo
echo "== Case 8: the guard is still red on a mid-run restart =="
run_start scene_midrun_restart
expect case8-start 0 1 0
MIDRUN=1
c8_rc=0
assert_relay "$RELAY" >"$OUT" 2>&1 || c8_rc=$?
cat "$OUT"
c8_ok=1; [ "$c8_rc" -eq 1 ] && c8_ok=0
check "case8: assert_relay fails the run" "$c8_ok" "rc=$c8_rc"
expect_has case8 "restarted 1 time(s) during"

echo "-- Case 8b: the same, with no fault line, so only the restart count shows it --"
run_start scene_midrun_restart
expect case8b-start 0 1 0
MIDRUN=2
c8b_rc=0
assert_relay "$RELAY" >"$OUT" 2>&1 || c8b_rc=$?
cat "$OUT"
c8b_ok=1; [ "$c8b_rc" -eq 1 ] && c8b_ok=0
check "case8b: assert_relay fails the run on the restart count alone" "$c8b_ok" "rc=$c8b_rc"

echo
echo "== Case 9: the lab itself fails to start =="
run_start scene_clean 45 1 0
expect case9 1 1 0
expect_has case9 "LAB START FAILED"
expect_lacks case9 "RELAY START FAULT"

echo
echo "== Case 10: the teardown between the two starts fails =="
run_start scene_segv_once 45 0 1
expect case10 1 1 1
expect_has case10 "$M1"
expect_has case10 "LAB START FAILED"

# --- Summary ----------------------------------------------------------
echo
echo "=============================================="
for r in "${RESULTS[@]}"; do
    echo "  $r"
done
echo "=============================================="
if [ "$FAILURES" -ne 0 ]; then
    echo "RESULT: $FAILURES assertion(s) FAILED"
    exit 1
fi
echo "RESULT: all assertions passed"
exit 0
