#!/bin/bash
# Tests for table_has() in table-check.sh, the firewall suite's check that a
# loaded nftables table contains a given rule.
#
# `docker` is replaced by a shell function that prints a canned
# `nft list table inet fips` listing in two chunks, with the matching rule in
# the first and a pause before the second. That is the shape of the defect this
# guards against: the reader has its match and exits while the producer is still
# writing. A check that pipes the producer into `grep -q` under pipefail sees
# the producer's SIGPIPE (141) and reports a rule that is present as absent.
# No containers are involved, so the suite is hermetic; it takes about two
# seconds.
#
# Run:
#   ./table-check-test.sh
# Exits 0 only if every case passes; non-zero if any case fails.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=SCRIPTDIR/table-check.sh
source "$SCRIPT_DIR/table-check.sh"

FAILURES=0
RULE='iifname != "notfips0" return'
STUB_MODE=present

# Stand-in for `docker exec <container> nft list table inet fips`. STUB_MODE
# picks a listing with the rule (present), one without it (absent), or an exec
# that fails (fail).
docker() {
    case "$STUB_MODE" in
        fail)
            echo "Error response from daemon: container is not running" >&2
            return 1
            ;;
        present)
            printf '%s\n' 'table inet fips {' '	chain input {' \
                '		type filter hook input priority filter; policy accept;' \
                "		$RULE"
            ;;
        absent)
            printf '%s\n' 'table inet fips {' '	chain input {' \
                '		type filter hook input priority filter; policy accept;' \
                '		iifname != "fips0" return'
            ;;
    esac
    sleep 0.2
    printf '%s\n' '		ct state established,related accept' \
        '		icmpv6 type echo-request accept' '		counter drop' '	}' '}'
    return 0
}

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

# Run table_has against the stand-in in the given mode; sets RC.
probe() {
    STUB_MODE="$1"
    RC=0
    table_has fips-fw-container-b "$RULE" 2>/dev/null || RC=$?
    return 0
}

for i in 1 2 3 4 5; do
    probe present
    check "rule present, writer still writing after the match (run $i): returns 0" \
        "$([ "$RC" -eq 0 ] && echo 0 || echo 1)" "rc=$RC"
done

probe absent
check "rule absent: returns 1" "$([ "$RC" -eq 1 ] && echo 0 || echo 1)" "rc=$RC"

probe fail
check "listing could not be read: returns 2" \
    "$([ "$RC" -eq 2 ] && echo 0 || echo 1)" "rc=$RC"

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "All table_has cases passed"
    exit 0
fi
echo "$FAILURES table_has check(s) failed"
exit 1
