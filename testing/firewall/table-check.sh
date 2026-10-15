#!/bin/bash
# Sourced by test.sh. Not run on its own.

# Return 0 if container $1's `inet fips` table listing contains the fixed text
# $2, 1 if it does not, and 2 if the listing could not be read.
#
# The listing is captured whole before it is matched. Piping `docker exec`
# straight into `grep -q` under pipefail fails a present rule: grep exits at
# its match, the exec client still writing the rest takes SIGPIPE (141), and
# pipefail reports the pipeline as failed. The here-string leaves no pipe, so
# the result does not depend on how much of the listing follows the match.
table_has() {
    local listing
    listing=$(docker exec "$1" nft list table inet fips) || return 2
    grep -qF -- "$2" <<<"$listing" && return 0
    return 1
}
