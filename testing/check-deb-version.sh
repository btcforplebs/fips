#!/bin/bash
# ── Debian package version derivation check ─────────────────────────────────
# A release candidate is tagged vX.Y.Z-rcN, because git refuses '~' in a ref
# name. dpkg reads X.Y.Z-rcN as revision rcN of X.Y.Z and sorts it ABOVE the
# release, so a host that installed the candidate is never upgraded by the
# release. package-linux.yml's "Derive Linux package version" step therefore
# maps the tag's pre-release suffix to '~' for the .deb, which dpkg sorts below.
#
# This runs that step's own text, taken from the workflow, rather than a copy,
# so the check and the workflow cannot drift apart. Cases:
#   refs/tags/v0.5.3      both versions 0.5.3
#   refs/tags/v0.5.3-rc1  deb 0.5.3~rc1, tarball and artifact 0.5.3-rc1, and
#                         dpkg orders 0.5.2 < 0.5.3~rc1 < 0.5.3
#   refs/heads/maint      deb equals the tarball version, which is
#                         <Cargo version>+maint.<height>.<hash>
#
# It also checks the wiring the derivation needs to have any effect: the job
# declares the deb_package_version output, the .deb build passes it as
# --version, and that step renames a '~' in the package file name to '-' (a
# GitHub release renames an asset with special characters in its name, which
# would leave checksums-linux.txt naming a file the release does not have).
# Those three are read from the text, not executed.
#
# Exit 0 = clean. Exit 1 = a case or a wiring check failed. Exit 2 = the check
# could not run (no dpkg, no PyYAML, the step not found, or an output missing);
# never treated as a pass.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKFLOW="$PROJECT_ROOT/.github/workflows/package-linux.yml"

cant() {
    echo "check-deb-version: $*; cannot verify the Debian version derivation" >&2
    exit 2
}

[ -f "$WORKFLOW" ] || cant "missing $WORKFLOW"
command -v dpkg >/dev/null 2>&1 || cant "dpkg not found"
command -v python3 >/dev/null 2>&1 || cant "python3 not found"
python3 -c "import yaml" >/dev/null 2>&1 || cant "python3 module 'yaml' not found"

WORK=$(mktemp -d) || cant "mktemp failed"
trap 'rm -rf "$WORK"' EXIT

# Pull the derivation step's run text, the job's declared outputs and the
# .deb build step's run text out of the workflow.
if ! python3 - "$WORKFLOW" "$WORK" <<'PY'
import sys
from pathlib import Path

import yaml

workflow, work = sys.argv[1], Path(sys.argv[2])
doc = yaml.safe_load(Path(workflow).read_text(encoding="utf-8"))
jobs = doc.get("jobs") or {}


def step_run(job, name):
    for step in (jobs.get(job) or {}).get("steps") or []:
        if step.get("name") == name:
            return step.get("run")
    return None


derive = step_run("determine-versioning", "Derive Linux package version")
build = step_run("build", "Build Debian package in the pinned container")
if not derive or not build:
    missing = "derivation" if not derive else "Debian build"
    print(f"check-deb-version: the {missing} step was not found in {workflow}",
          file=sys.stderr)
    sys.exit(2)
(work / "derive.sh").write_text(derive, encoding="utf-8")
(work / "build.sh").write_text(build, encoding="utf-8")
outputs = (jobs.get("determine-versioning") or {}).get("outputs") or {}
(work / "outputs").write_text(
    "".join(f"{k}={v}\n" for k, v in outputs.items()), encoding="utf-8")
PY
then
    exit 2
fi

FAILED=0
ok()  { echo "  PASS  $*"; }
bad() { echo "  FAIL  $*"; FAILED=$((FAILED + 1)); }

# Run the derivation for one ref and load its outputs into LINUX and DEB.
# Exits 2 when the step fails or does not write both outputs: no version was
# established, which is not a failed case.
derive() {
    local ref="$1" out="$WORK/github_output"
    : > "$out"
    if ! (cd "$PROJECT_ROOT" && GITHUB_OUTPUT="$out" GITHUB_REF="$ref" \
            GITHUB_REF_NAME="${ref#refs/*/}" bash -eo pipefail "$WORK/derive.sh") >"$WORK/derive.log" 2>&1; then
        echo "check-deb-version: the derivation failed for $ref:" >&2
        cat "$WORK/derive.log" >&2
        exit 2
    fi
    LINUX=$(sed -n 's/^linux_package_version=//p' "$out")
    DEB=$(sed -n 's/^deb_package_version=//p' "$out")
    if [ -z "$LINUX" ] || [ -z "$DEB" ]; then
        cant "the derivation for $ref did not write both outputs (linux '$LINUX', deb '$DEB')"
    fi
    return 0
}

# Record whether dpkg orders $1 $2 $3 (lt, gt, ...).
expect_order() {
    if dpkg --compare-versions "$1" "$2" "$3"; then
        ok "dpkg: $1 $2 $3"
    else
        bad "dpkg: $1 $2 $3 does not hold"
    fi
    return 0
}

# Record whether a derived version equals the expected one.
expect_eq() {
    local label="$1" got="$2" want="$3"
    if [ "$got" = "$want" ]; then
        ok "$label: $got"
    else
        bad "$label: $got (want $want)"
    fi
    return 0
}

echo "Release tag refs/tags/v0.5.3"
derive refs/tags/v0.5.3
expect_eq "linux_package_version" "$LINUX" "0.5.3"
expect_eq "deb_package_version" "$DEB" "0.5.3"

echo "Candidate tag refs/tags/v0.5.3-rc1"
derive refs/tags/v0.5.3-rc1
expect_eq "linux_package_version" "$LINUX" "0.5.3-rc1"
expect_eq "deb_package_version" "$DEB" "0.5.3~rc1"
expect_order "$DEB" lt 0.5.3
expect_order "$DEB" gt 0.5.2

echo "Branch refs/heads/maint"
derive refs/heads/maint
CRATE=$(awk -F'"' '/^version = /{print $2; exit}' "$PROJECT_ROOT/Cargo.toml")
HEIGHT=$(git -C "$PROJECT_ROOT" rev-list --count HEAD) || cant "git rev-list failed"
HASH=$(git -C "$PROJECT_ROOT" rev-parse --short HEAD) || cant "git rev-parse failed"
[ -n "$CRATE" ] || cant "no version in Cargo.toml"
expect_eq "linux_package_version" "$LINUX" "${CRATE}+maint.${HEIGHT}.${HASH}"
expect_eq "deb_package_version" "$DEB" "$LINUX"

echo "Wiring"
# shellcheck disable=SC2016  # the ${{ }} expressions are workflow text, not shell
if grep -qxF 'deb_package_version=${{ steps.linux_version.outputs.deb_package_version }}' "$WORK/outputs"; then
    ok "determine-versioning declares the deb_package_version output"
else
    bad "determine-versioning does not declare deb_package_version from the derivation step"
fi
# shellcheck disable=SC2016
if grep -qF -- '--version "${{ needs.determine-versioning.outputs.deb_package_version }}"' "$WORK/build.sh"; then
    ok "the .deb build passes deb_package_version as --version"
else
    bad "the .deb build does not pass deb_package_version as --version"
fi
if grep -qF "tr '~' '-'" "$WORK/build.sh"; then
    ok "the .deb build renames a '~' in the package file name"
else
    bad "the .deb build does not rename a '~' in the package file name"
fi

echo
if [ "$FAILED" -eq 0 ]; then
    echo "check-deb-version: all checks passed"
    exit 0
fi
echo "check-deb-version: $FAILED check(s) failed"
exit 1
