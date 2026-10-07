#!/bin/bash
# Shared relay verdict for the NAT-lab suites.
#
# Source this file to get relay_verdict(), relay_log(), assert_relay(),
# relay_start_gate() and relay_lab_start().
#
# Usage:
#   source "$ROOT_DIR/testing/lib/relay-verdict.sh"
#   relay_lab_start <relay-container> <clients> <timeout-s> <start-fn> <stop-fn>
#   relay_verdict <relay-container>   # in a failure dump
#   assert_relay <relay-container>    # last check on a success path
#
# The lab's Nostr relay is a third-party container (strfry), and it has died
# mid-run: once on a SIGSEGV twelve milliseconds after both nodes had
# connected, and several times since on an internal assertion that aborts it
# the instant two clients connect together. Every symptom under that is a
# correct report of a dead relay: subscriptions dropped, no advert consumed,
# empty peer lists, and a run that fails on the peer-count wait. That verdict
# is indistinguishable from a product failure unless the relay's state is
# stated, and the only evidence of the real cause was one container-log line
# far above the summary. relay_verdict says whose failure it was, in a line a
# reader of the output can find.
#
# The crash is strfry's own. It reproduces with the unmodified upstream image
# and upstream's default config, with no FIPS code involved: a few fresh relays
# in a hundred crashed when two plain websocket clients made their first
# connections together, and none crashed once one client had connected first.
# The pinned build is upstream's newest. So the lab starts through
# relay_lab_start, which retries the start once if the relay faulted in its
# start window, before the scenario has done anything. A relay fault after that
# window, and a lab that fails to start for any other reason, still fail the
# suite as before.

# What a relay fault leaves in its log. One copy, for every check here.
RELAY_FAULTS="caught a signal|SIGSEGV|SIGABRT|terminate called"

# Print the relay's whole container log to stderr, between marker lines.
#
# Not truncated: a relay abort's context can sit anywhere in the log, which
# spans every restart of the container, and the suite's teardown deletes the
# container and with it the only copy.
relay_log() {
    local container="$1" logs=""
    if ! logs="$(docker logs --timestamps "$container" 2>&1)"; then
        echo "  ($container's log could not be read)" >&2
        return 0
    fi
    echo "--- $container: full log begin ---" >&2
    printf '%s\n' "$logs" >&2
    echo "--- $container: full log end ---" >&2
}

# State the relay's own condition, in its own words.
#
# Returns 0 when the run had a relay event (the relay is gone, not running,
# restarted, faulted, or its health could not be read) and 1 when the relay
# was running with no fault in its log. When the relay still exists and its
# log can be read, an event also prints its full log. Failure dumps call it
# first; success paths go through assert_relay, which turns an event into a
# failure.
#
# A relay whose state or log cannot be read has not been shown to be healthy,
# so that case is reported as unestablished rather than as "not the relay".
relay_verdict() {
    local container="$1"
    local state="" status="" exit_code="" restarts="" logs=""
    local faults="$RELAY_FAULTS"

    state="$(docker inspect \
        -f '{{.State.Status}} {{.State.ExitCode}} {{.RestartCount}}' \
        "$container" 2>/dev/null)" || state=""

    if [ -z "$state" ]; then
        echo "RELAY FAILURE: $container is gone; whatever this run" \
             "asserted about peering happened without a relay" >&2
        return 0
    fi

    read -r status exit_code restarts <<<"$state"

    if [ "$status" != "running" ]; then
        echo "RELAY FAILURE: $container is $status (exit $exit_code);" \
             "the assertions in this run are downstream of that, not of the" \
             "nodes" >&2
        relay_log "$container"
        return 0
    fi

    # docker logs spans every restart of the same container, so the fault
    # lines of the run that died are still readable here.
    if [ "${restarts:-0}" -gt 0 ]; then
        echo "RELAY FAILURE: $container restarted $restarts time(s) during" \
             "this run under its restart policy; the nodes lost their" \
             "subscriptions each time and had to reconnect" >&2
        if logs="$(docker logs "$container" 2>&1)"; then
            grep -E "$faults" <<<"$logs" >&2 || true
        else
            echo "  (its logs could not be read, so the fault lines are" \
                 "not shown)" >&2
        fi
        relay_log "$container"
        return 0
    fi

    if ! logs="$(docker logs "$container" 2>&1)"; then
        echo "RELAY HEALTH NOT ESTABLISHED: could not read" \
             "$container's logs, so a crash cannot be ruled in or out" >&2
        return 0
    fi

    if grep -Eq "$faults" <<<"$logs"; then
        echo "RELAY FAILURE: $container faulted during this run:" >&2
        grep -E "$faults" <<<"$logs" >&2
        relay_log "$container"
        return 0
    fi

    echo "relay: $container running, no fault in its log — this run's" \
         "verdict is about the nodes"
    return 1
}

# Fail a success path whose relay had an event during the run.
#
# A relay that restarted dropped every node's subscription, so assertions
# that passed across it may not have exercised what they claim to. Passing
# with a note hid that, and the teardown that followed deleted the relay's
# log, so the abort could not be diagnosed.
assert_relay() {
    local container="$1"
    if relay_verdict "$container"; then
        echo "FAIL: the relay was not shown to stay up and healthy for the" \
             "whole run, so the assertions above are not established (relay" \
             "lines above)" >&2
        return 1
    fi
    return 0
}

# Report whether the relay faulted in its start window.
#
# The window opens when the lab is started and closes once the log holds at
# least <clients> websocket connects and four further half-second polls have
# passed with no fault. The observed crashes came within milliseconds of the
# first connects, so two seconds is a wide margin. A plain TCP probe of the
# relay's port, which the node entrypoint uses to wait for it, is not a
# websocket connect and does not appear in the count.
#
# Returns 1, after naming what was seen and printing the relay's full log, when
# in the window the relay is gone, not running, has restarted, has a fault line
# in its log, or its state or log cannot be read: none of those shows a healthy
# start. Returns 0 when the window closes clean, and also when <timeout-s> worth
# of polls pass without <clients> connects. That second case is a note, not a
# verdict: the gate exists to catch a start crash, the scenario's own waits
# report nodes that never connect, and assert_relay still catches any relay
# restart from here on.
relay_start_gate() {
    local container="$1" clients="$2" timeout="$3"
    local polls=$(( timeout * 2 )) settle=4 poll=0 held=0
    local state="" status="" restarts="" logs="" connects=0 seen=""

    while :; do
        seen=""
        if ! state="$(docker inspect -f '{{.State.Status}} {{.RestartCount}}' \
                "$container" 2>/dev/null)" || [ -z "$state" ]; then
            seen="is gone, or its state could not be read"
        else
            read -r status restarts <<<"$state"
            if [ "$status" != "running" ]; then
                seen="is $status"
            elif [ "${restarts:-0}" -gt 0 ]; then
                seen="restarted $restarts time(s)"
            elif ! logs="$(docker logs "$container" 2>&1)"; then
                seen="has a log that could not be read"
            elif grep -Eq "$RELAY_FAULTS" <<<"$logs"; then
                seen="logged a fault"
            fi
        fi

        if [ -n "$seen" ]; then
            echo "relay start: $container $seen in its start window" >&2
            if logs="$(docker logs "$container" 2>&1)"; then
                grep -E "$RELAY_FAULTS" <<<"$logs" >&2 || true
            fi
            relay_log "$container"
            return 1
        fi

        connects="$(grep -cF '] Connect from ' <<<"$logs" || true)"
        if [ "${connects:-0}" -ge "$clients" ]; then
            if [ "$held" -ge "$settle" ]; then
                echo "relay start: $container served $connects connect(s)" \
                     "with no fault in its start window"
                return 0
            fi
            held=$(( held + 1 ))
        elif [ "$poll" -ge "$polls" ]; then
            echo "relay start: start window not established for $container:" \
                 "$connects of $clients client connect(s) after ${timeout}s;" \
                 "the scenario's own waits judge the nodes from here"
            return 0
        fi
        poll=$(( poll + 1 ))
        sleep 0.5
    done
}

# Start the lab, and start it once more if the relay faulted in its start
# window.
#
# <start-fn> starts the whole lab and returns non-zero if any step failed. It
# runs under this function's caller's `||`, where `set -e` does not apply, so
# it must check each step itself. A failed start is not a relay fault and is
# not retried. On a relay fault the lab is torn down with <stop-fn> and started
# again, so the second attempt has a fresh relay container, volume and nodes,
# and a restart count of zero for assert_relay to judge. A second fault fails.
#
# The first attempt's fault and the relay's full log stay in the output under a
# RELAY START FAULT line, so a retried start is never silent.
relay_lab_start() {
    local container="$1" clients="$2" timeout="$3" start_fn="$4" stop_fn="$5"
    local attempt

    for attempt in 1 2; do
        if ! "$start_fn"; then
            echo "LAB START FAILED: $start_fn exited non-zero on attempt" \
                 "$attempt; that is not a relay fault, so it is not retried" >&2
            return 1
        fi
        if relay_start_gate "$container" "$clients" "$timeout"; then
            return 0
        fi
        if [ "$attempt" -eq 2 ]; then
            echo "RELAY START FAULT (attempt 2 of 2): $container faulted in" \
                 "its start window again; the relay faulted on both starts;" \
                 "failing" >&2
            return 1
        fi
        echo "RELAY START FAULT (attempt 1 of 2): $container faulted in its" \
             "start window, before the scenario began; tearing the lab down" \
             "and starting it once more" >&2
        if ! "$stop_fn"; then
            echo "LAB START FAILED: $stop_fn exited non-zero while tearing" \
                 "the lab down for its second start" >&2
            return 1
        fi
    done
    return 1
}
