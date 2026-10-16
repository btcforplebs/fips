#!/bin/bash
# ── Crate publication check ─────────────────────────────────────────────────
# Checks that the root package would publish to crates.io, without publishing
# anything. crate.yml runs it on every push to maint and on every v* tag, and
# its publish job runs only after this passes.
#
# What it checks:
#   1. The package is named fips-mesh (crates.io's `fips` is an unrelated
#      crate), and on a tag its version matches the tag: v0.5.3 needs 0.5.3,
#      v0.5.3-rc1 needs 0.5.3-rc.1.
#   2. The metadata crates.io enforces at upload and `cargo publish --dry-run`
#      does not: at most five keywords, each at most 20 characters of ASCII
#      letters, digits, `-`, `_` or `+` and starting with a letter or digit
#      (crates.io's crates_io_database keyword rule), and at most five
#      categories, each one of crates.io's category slugs (fetched from
#      crates.io).
#   3. `cargo publish --dry-run --locked` packages the crate and builds it from
#      the unpacked copy. Nothing is uploaded.
#   4. The .crate is under crates.io's 10 MiB upload limit.
#   5. The library's unit tests pass when run from the unpacked .crate, so a
#      file the tests read but the `include` list leaves out fails here rather
#      than for whoever builds the published crate. The dry run alone does not
#      catch that: a file read only by test code is not needed to build.
#
# WHAT THIS DOES NOT COVER, so a green run is not read as "the publish will
# succeed": the registry token, ownership of the crate name, and anything
# crates.io decides only at upload (a version already published, its rate
# limits). Those are exercised only by the real publish. Nor does it catch a
# file left out of `include` that neither the build nor any lib test reads.
#
# Usage: testing/check-crate.sh [--allow-dirty] [<git ref>]
#   <git ref> defaults to $GITHUB_REF; a refs/tags/v* ref turns on the version
#   check. --allow-dirty passes through to cargo, for a local run on an
#   uncommitted tree.
#
# Exit 0 = clean. Exit 1 = a check failed. Exit 2 = the check could not run
# (no cargo or jq, crates.io unreachable, the .crate missing); never treated
# as a pass.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CRATE=fips-mesh
MAX_BYTES=$((10 * 1024 * 1024))
UA="fips-crate-check (https://github.com/jmcorgan/fips)"

cant() {
    echo "check-crate: $*; cannot verify the crate" >&2
    exit 2
}

fail() {
    echo "check-crate: FAIL: $*" >&2
    exit 1
}

DIRTY=()
REF="${GITHUB_REF:-}"
for arg in "$@"; do
    case "$arg" in
        --allow-dirty) DIRTY=(--allow-dirty) ;;
        -*) echo "check-crate: unknown option $arg" >&2; exit 2 ;;
        *) REF="$arg" ;;
    esac
done

command -v cargo >/dev/null || cant "cargo not found"
command -v jq >/dev/null || cant "jq not found"
command -v curl >/dev/null || cant "curl not found"
cd "$PROJECT_ROOT" || cant "cannot enter $PROJECT_ROOT"

meta=$(cargo metadata --locked --no-deps --format-version 1) || cant "cargo metadata failed"
root=$(jq -c --arg m "$PROJECT_ROOT/Cargo.toml" \
    '.packages[] | select(.manifest_path == $m)' <<<"$meta")
[ -n "$root" ] || cant "no package for $PROJECT_ROOT/Cargo.toml"

name=$(jq -r .name <<<"$root")
version=$(jq -r .version <<<"$root")
[ "$name" = "$CRATE" ] || fail "root package is named $name, expected $CRATE"
echo "check-crate: $name $version"

# 1. Version against the tag.
case "$REF" in
    refs/tags/v*)
        tag="${REF#refs/tags/v}"
        want=$(sed -E 's/-(rc|beta|alpha)([0-9]+)$/-\1.\2/' <<<"$tag")
        [ "$version" = "$want" ] || fail "tag v$tag needs version $want, Cargo.toml has $version"
        echo "check-crate: version matches tag v$tag"
        ;;
esac

# 2. Upload-time metadata rules.
nkw=$(jq '.keywords | length' <<<"$root")
[ "$nkw" -le 5 ] || fail "$nkw keywords, crates.io allows 5"
while IFS= read -r kw; do
    [[ "$kw" =~ ^[A-Za-z0-9][A-Za-z0-9_+-]{0,19}$ ]] || fail "keyword '$kw' is not a valid crates.io keyword"
done < <(jq -r '.keywords[]' <<<"$root")

ncat=$(jq '.categories | length' <<<"$root")
[ "$ncat" -le 5 ] || fail "$ncat categories, crates.io allows 5"
if [ "$ncat" -gt 0 ]; then
    slugs=$(curl -fsS -A "$UA" https://crates.io/api/v1/category_slugs) \
        || cant "could not fetch crates.io category slugs"
    jq -e '.category_slugs | type == "array" and length > 0' <<<"$slugs" >/dev/null \
        || cant "crates.io category slugs came back in an unexpected shape"
    while IFS= read -r cat; do
        jq -e --arg c "$cat" '.category_slugs | any(.slug == $c)' <<<"$slugs" >/dev/null \
            || fail "category '$cat' is not a crates.io category slug"
    done < <(jq -r '.categories[]' <<<"$root")
fi
echo "check-crate: $nkw keywords and $ncat categories accepted"

# 3. Package and build from the unpacked copy.
cargo publish --dry-run --locked "${DIRTY[@]}" -p "$CRATE"
rc=$?
[ "$rc" -eq 0 ] || fail "cargo publish --dry-run exited $rc"

# cargo publish --dry-run leaves the .crate in target/package/tmp-crate/
# (cargo 1.94); cargo package leaves it in target/package/. Copy it to one
# path, target/crate-check/, which crate.yml uploads.
target=$(jq -r .target_directory <<<"$meta")
file=""
for f in "$target/package/tmp-crate/$CRATE-$version.crate" "$target/package/$CRATE-$version.crate"; do
    [ -f "$f" ] && { file="$f"; break; }
done
[ -n "$file" ] || cant "$CRATE-$version.crate not found under $target/package after the dry run"
mkdir -p "$target/crate-check" || cant "cannot create $target/crate-check"
cp "$file" "$target/crate-check/" || cant "cannot copy $file"
file="$target/crate-check/$CRATE-$version.crate"

# 4. Upload size limit.
bytes=$(stat -c %s "$file" 2>/dev/null || stat -f %z "$file") || cant "cannot read the size of $file"
[ "$bytes" -le "$MAX_BYTES" ] || fail "$file is $bytes bytes, over crates.io's $MAX_BYTES"
echo "check-crate: $file is $bytes bytes"

# 5. Unit tests from the unpacked crate.
work=$(mktemp -d) || cant "mktemp failed"
trap 'rm -rf "$work"' EXIT
tar -xzf "$file" -C "$work" || cant "cannot unpack $file"
(cd "$work/$CRATE-$version" && CARGO_TARGET_DIR="$work/target" cargo test --lib --locked)
rc=$?
[ "$rc" -eq 0 ] || fail "lib tests from the unpacked crate exited $rc"

echo "check-crate: OK"
exit 0
