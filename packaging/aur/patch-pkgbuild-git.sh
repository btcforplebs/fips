#!/usr/bin/env bash
# Patch packaging/aur/PKGBUILD-git in place with the b2sums of the local
# assets it ships (fips.sysusers and fips.tmpfiles).
#
# Used by both jobs of the fips-git AUR workflow, the lint and the publish,
# so the file it publishes is the file it linted, with sums that match the
# assets published beside it. Exits nonzero if the sums did not land.
#
# Run from the repository root.

set -euo pipefail

SYSUSERS_SUM=$(b2sum packaging/aur/fips.sysusers | awk '{print $1}')
TMPFILES_SUM=$(b2sum packaging/aur/fips.tmpfiles | awk '{print $1}')
if [ -z "$SYSUSERS_SUM" ] || [ -z "$TMPFILES_SUM" ]; then
  echo "Failed to compute asset b2sums"; exit 1
fi
awk -v s1="$SYSUSERS_SUM" -v s2="$TMPFILES_SUM" '
  /^b2sums=\(/ { in_block=1; count=0 }
  in_block {
    count++
    if (count == 2) sub(/[a-f0-9]{128}/, s1)
    if (count == 3) sub(/[a-f0-9]{128}/, s2)
    if ($0 ~ /\)/) in_block=0
  }
  { print }
' packaging/aur/PKGBUILD-git > packaging/aur/PKGBUILD-git.new
mv packaging/aur/PKGBUILD-git.new packaging/aur/PKGBUILD-git

# The lint job and the publish job run this under different awks. One that
# does not honour the {128} interval above would leave the sums unpatched and
# still exit 0, so confirm the file now carries the computed sums.
block=$(sed -n '/^b2sums=(/,/)/p' packaging/aur/PKGBUILD-git)
for entry in "2 fips.sysusers $SYSUSERS_SUM" "3 fips.tmpfiles $TMPFILES_SUM"; do
  read -r n name sum <<<"$entry"
  case "$(printf '%s\n' "$block" | sed -n "${n}p")" in
    *"'$sum'"*) ;;
    *) echo "PKGBUILD-git b2sums entry $n is not the $name sum after patching" >&2
       exit 1 ;;
  esac
done

echo "Patched PKGBUILD-git b2sums:"
awk '/^b2sums=\(/,/\)$/' packaging/aur/PKGBUILD-git
