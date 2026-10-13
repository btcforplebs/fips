#!/bin/sh
# fips-gateway init script scenarios, run inside an openwrt/rootfs image so the
# image's own rc.common, procd.sh, flock and uci run the script under ash.
#
# Driven by testing/openwrt/maintainer-scripts-test.sh, once per pinned image,
# in a container with no network. There is no procd and no ubusd: ubus fails at
# once with "Failed to connect to ubus", so rc.common's procd calls return
# quickly and procd_running reports nothing running, unless a case installs
# the ubus stub. The gateway is a stub that records its open descriptors and
# sleeps until it is signalled; /etc/init.d/network, odhcpd and dnsmasq are
# recorders that log each call to $CALLS.
#
# Seams:
#   INIT_GATEWAY  the init script under test; default the one built into the
#                 .ipk, as package-test.sh --keep extracts it under /apk.
#   INIT_CASES    case function names to run, separated by spaces; default all.
#
# Facts about the images this allows for: /var links to /tmp and /var/lock
# does not exist, so it is created; there is no timeout binary, so a command
# that may hang is bounded by a background sleep and kill; there is no pkill,
# and sleep takes whole seconds only.
#
# Every case that reaches its end is counted, and a run that counts fewer
# cases than it selected exits 2.
#
# Exit 0 = every case passed. Exit 1 = at least one failed. Exit 2 = the
# harness could not run; never treated as a pass.

set -u

INIT_GATEWAY="${INIT_GATEWAY:-/apk/ipk-root/etc/init.d/fips-gateway}"
INIT_CASES="${INIT_CASES:-}"

INIT=/etc/init.d/fips-gateway
LOCK=/var/lock/procd_fips-gateway.lock
CALLS=/tmp/init-calls
FDS=/tmp/init-gateway-fds
SUPLOG=/tmp/init-supervise.log
UBUS_REAL=/tmp/init-ubus.real

# The number of cases in the full run, counted by hand from the list at the
# end of this file. A run that completes fewer exits 2.
ALL_CASES=1

FAILURES=0
CASES=0
RAN=0
CUR=""

ok() {
	CASES=$((CASES + 1))
	echo "  ok   $CUR: $*"
	return 0
}

bad() {
	CASES=$((CASES + 1))
	FAILURES=$((FAILURES + 1))
	echo "  FAIL $CUR: $*"
	return 0
}

harness_fail() {
	echo "init-scenarios: $*" >&2
	exit 2
}

# check <description> <command...>: passes when the command succeeds.
check() {
	local d="$1"
	shift
	if "$@"; then ok "$d"; else bad "$d"; fi
	return 0
}

# precond <description> <command...>: like check, but returns the verdict so
# the case can skip to its end.
precond() {
	local d="$1"
	shift
	if "$@"; then
		ok "precondition: $d"
		return 0
	fi
	bad "precondition: $d"
	return 1
}

begin() {
	CUR="$1"
	echo "  $CUR"
}

finish() {
	RAN=$((RAN + 1))
	echo "  done $CUR"
}

# bounded <seconds> <command...>: run the command, killing it after <seconds>.
# Returns its status, or 124 when it had to be killed.
bounded() {
	local secs="$1" pid killer rc
	shift
	rm -f /tmp/init-timedout
	"$@" &
	pid=$!
	(
		sleep "$secs"
		if kill -0 "$pid" 2>/dev/null; then
			touch /tmp/init-timedout
			kill -KILL "$pid"
		fi
	) &
	killer=$!
	rc=0
	wait "$pid" || rc=$?
	kill "$killer" 2>/dev/null
	wait "$killer" 2>/dev/null
	[ -e /tmp/init-timedout ] && return 124
	return "$rc"
}

# Kill every process whose command line matches $1.
kill_matching() {
	local p
	for p in $(pgrep -f "$1"); do
		kill "$p" 2>/dev/null
	done
	return 0
}

# A recorder installed as $1: logs its own name and arguments. The path is
# removed first, since it may be a link to busybox.
recorder() {
	rm -f "$1"
	printf '#!/bin/sh\necho "%s $*" >> %s\nexit 0\n' "${1##*/}" "$CALLS" > "$1"
	chmod 0755 "$1"
}

# The image as each case starts from: the init script under test, the stub
# gateway and the recorders, a gateway-enabled fips.yaml, a LAN interface in
# the network config, no boot links, and the real ubus.
reset() {
	kill_matching "$INIT supervise"
	kill_matching /usr/bin/fips-gateway
	rm -f "$CALLS" "$FDS" "$SUPLOG" /var/run/fips-gateway.pid /var/run/fips-gateway-install-hold
	mkdir -p /var/lock /var/run /etc/fips /etc/rc.d
	cp "$INIT_GATEWAY" "$INIT" || harness_fail "cannot install $INIT_GATEWAY"
	chmod 0755 "$INIT"
	rm -f /etc/rc.d/S??fips-gateway /etc/rc.d/K??fips-gateway
	cat > /usr/bin/fips-gateway <<STUB
#!/bin/sh
ls /proc/\$\$/fd > $FDS.tmp && mv $FDS.tmp $FDS
trap 'exit 0' TERM INT
while :; do sleep 1; done
STUB
	chmod 0755 /usr/bin/fips-gateway
	recorder /etc/init.d/network
	recorder /etc/init.d/odhcpd
	recorder /etc/init.d/dnsmasq
	cat > /etc/fips/fips.yaml <<'YAML'
gateway:
  enabled: true
  pool: "fd01::/112"
  lan_interface: br-lan
YAML
	cat > /etc/config/network <<'UCI'
config interface 'lan'
	option device 'br-lan'
	option proto 'static'
	option ipaddr '192.168.1.1'
	option netmask '255.255.255.0'
UCI
	[ -e "$UBUS_REAL" ] && cp "$UBUS_REAL" /bin/ubus
	: > "$CALLS"
	return 0
}

# Start supervise as procd would, and wait for the stub gateway to record its
# descriptors.
supervise_start() {
	"$INIT" supervise > "$SUPLOG" 2>&1 &
	SUP=$!
	local i=0
	while [ ! -s "$FDS" ] && [ "$i" -lt 10 ]; do
		sleep 1
		i=$((i + 1))
	done
	[ -s "$FDS" ]
}

# Stop supervise as procd would: SIGTERM to the shell, which passes it on,
# and wait up to 10 seconds for its teardown to finish, so it cannot run into
# the next case. Only this shell can wait for supervise, its child, so the
# wait runs here and a background sleep kills supervise if it overruns.
supervise_stop() {
	local killer
	kill -TERM "$SUP" 2>/dev/null
	(
		sleep 10
		kill -KILL "$SUP" 2>/dev/null
	) &
	killer=$!
	wait "$SUP" >/dev/null 2>&1
	kill "$killer" 2>/dev/null
	wait "$killer" 2>/dev/null
	kill_matching /usr/bin/fips-gateway
	return 0
}

no_fd_1000() { ! grep -qx 1000 "$FDS"; }
lock_free() { flock -n "$LOCK" true; }
stop_returns() { bounded 10 "$INIT" stop >/dev/null 2>&1; [ "$?" -ne 124 ]; }

# ── Cases ───────────────────────────────────────────────────────────────────

# procd runs `fips-gateway supervise`; rc.common took procd's service lock on
# fd 1000 when it sourced procd.sh. Held for the gateway's lifetime, it makes
# every later stop, restart and reload wait forever.
lock_released_while_gateway_runs() {
	begin lock_released_while_gateway_runs
	reset
	if precond "supervise starts the stub gateway" supervise_start; then
		check "L1: the gateway does not hold fd 1000" no_fd_1000
		check "L2: procd's service lock is free while the gateway runs" lock_free
		check "L3: stop returns within 10 s while the gateway runs" stop_returns
	fi
	supervise_stop
	finish
}

# ── Runner ──────────────────────────────────────────────────────────────────

[ -f "$INIT_GATEWAY" ] || harness_fail "no init script at $INIT_GATEWAY"
for tool in flock uci pgrep; do
	command -v "$tool" >/dev/null 2>&1 || harness_fail "$tool is missing from the image"
done
for f in /etc/rc.common /lib/functions/procd.sh; do
	[ -f "$f" ] || harness_fail "the image has no $f"
done
cp /bin/ubus "$UBUS_REAL" || harness_fail "cannot save /bin/ubus"

ALL="lock_released_while_gateway_runs"

if [ -n "$INIT_CASES" ]; then
	SELECTED="$INIT_CASES"
	EXPECTED=$(echo "$INIT_CASES" | wc -w)
	for c in $INIT_CASES; do
		printf '%s\n' "$ALL" | grep -qxF "$c" || harness_fail "unknown case in INIT_CASES: $c"
	done
else
	SELECTED="$ALL"
	EXPECTED=$ALL_CASES
fi

for c in $SELECTED; do
	"$c"
done

echo ""
echo "ran $RAN of $EXPECTED cases"
if [ "$RAN" -ne "$EXPECTED" ]; then
	echo "init-scenarios: $((EXPECTED - RAN)) case(s) did not reach their end" >&2
	exit 2
fi
if [ "$FAILURES" -eq 0 ]; then
	echo "init-scenarios: all $CASES checks passed"
	exit 0
fi
echo "init-scenarios: $FAILURES of $CASES checks failed"
exit 1
