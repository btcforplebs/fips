# FIPS OpenWrt Package (apk)

Builds a FIPS `.apk` for **OpenWrt 25+**, where apk-tools is the mandatory
package manager. apk is also available opt-in on **24.10** (where opkg remains
the default). For OpenWrt 24.x and earlier, the `.ipk` package in
[`../openwrt-ipk/`](../openwrt-ipk/) still works.

Like the `.ipk` build, this is **SDK-free**: it cross-compiles with
`cargo-zigbuild` and assembles the package directly — no OpenWrt SDK image. The
`.ipk` format is a plain tar.gz we can hand-roll, but the `.apk` (apk-tools v3
ADB) container is not, so we drive the official `apk mkpkg` applet — the same
tool OpenWrt's own [`include/package-pack.mk`](https://github.com/openwrt/openwrt/blob/main/include/package-pack.mk)
calls. The only extra requirement over the `.ipk` build is the `apk` binary.

## Layout

| File | Purpose |
|---|---|
| `build-apk.sh` | Cross-compile + assemble the `.apk` via `apk mkpkg` |
| `apk-version.sh` | Map a release tag / commit height to an apk-tools-valid version |
| `apk-version.test.sh` | Case-table test for `apk-version.sh` (`sh apk-version.test.sh`) |

The installed-filesystem payload (init scripts, `fips.yaml`, sysctl drop-ins,
uci-defaults, …) is **shared** with the `.ipk` package — there is one
canonical copy in [`../openwrt-ipk/files/`](../openwrt-ipk/files/). `build-apk.sh`
stages from there, so the two packages ship the same files apart from one
staged rewrite: `build-apk.sh` changes `ethernet.wan.interface` in the staged
`fips.yaml` from `eth0` to `wan`, the OpenWrt 25 DSA port name. Keep the
staging block in `build-apk.sh` in sync with `../openwrt-ipk/build-ipk.sh`.

## Versioning

apk-tools enforces a strict version grammar
(`<digit>(.<digit>)*(_<suffix><digit>*)*(-r<N>)`). `apk-version.sh` builds a
valid version from structured inputs rather than rewriting an already-flattened
string:

| Input | apk version |
|---|---|
| `tag v1.2.3` | `1.2.3-r0` |
| `tag v1.2.3-rc1` | `1.2.3_rc1-r0` |
| `dev 1234` (commit height) | `0.0.0_git1234-r0` |

The human-readable version (`v1.2.3`, `master.123.abcdef0`) is still used for the
artifact filename; only the metadata embedded in the package is normalized.

## Building

### Prerequisites

| Requirement | Notes |
|---|---|
| `cargo install cargo-zigbuild` + `zig` | Rust musl cross-compilation (as for `.ipk`) |
| apk-tools v3 `apk` binary | Provides `apk mkpkg`; not packaged for most distros — build from source |
| `fakeroot` | Optional; makes packaged files root-owned on an unprivileged build host |

apk-tools is not in Debian/Ubuntu repos, so build the pinned release from source.
Pin the same commit the targeted OpenWrt release ships (see
`package/system/apk/Makefile` upstream) so the `.apk` is readable by the device's
`apk`. CI builds **3.0.5** (`b5a31c0d…`):

```bash
sudo apt-get install -y build-essential meson ninja-build pkg-config \
  zlib1g-dev libssl-dev libzstd-dev liblzma-dev lua5.4-dev scdoc
git clone https://gitlab.alpinelinux.org/alpine/apk-tools.git
cd apk-tools && git checkout b5a31c0d865342ad80be10d68f1bb3d3ad9b0866
meson setup build && ninja -C build src/apk
export APK_BIN="$PWD/build/src/apk"
```

#### Or package in an Alpine container

Instead of building apk-tools, cross-compile on the host and package in an
`alpine:3.23` container, whose own `apk` is apk-tools 3.0.8; OpenWrt 25.12's
apk-tools 3.0.5 installs what it builds. Run from the repo root:

```bash
ARCH=aarch64 TRIPLE=aarch64-unknown-linux-musl
cargo zigbuild --release --target "$TRIPLE" \
  --bin fips --bin fipsctl --bin fipstop --bin fips-gateway
TARGET_DIR=$(cargo metadata --format-version 1 --no-deps |
  sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
docker run --rm -w /src -v "$PWD:/src" \
  -v "$TARGET_DIR/$TRIPLE/release:/bins:ro" \
  -e PKG_VERSION="$(git describe --tags --always --dirty)" \
  -e APK_VERSION="$(sh packaging/openwrt-apk/apk-version.sh auto)" \
  -e APK_BIN=apk -e ARCH="$ARCH" alpine:3.23 \
  sh -c 'apk add --no-cache bash &&
    bash packaging/openwrt-apk/build-apk.sh --arch "$ARCH" --bin-dir /bins'
```

Pass both versions from the host as shown. The container has no `git`, or git
refuses the bind-mounted checkout as owned by another user, and without them
the build falls back, without an error, to `PKG_VERSION` `0.1.0` and
`APK_VERSION` `0.0.0_git0-r0`, which sorts below any installed development
build. The package is written to `dist/` owned by root.

### Build the package

```bash
# from the repo root
./packaging/openwrt-apk/build-apk.sh --arch aarch64    # or x86_64; releases publish these two
```

Output: `dist/fips_<version>_<openwrt-arch>.apk`. Override the version with
`PKG_VERSION` (filename) and `APK_VERSION` (embedded metadata); otherwise both are
derived from git.

## Installing on the router

Packages are **unsigned** (the same posture as our `.ipk`), so install with
`--allow-untrusted`:

```bash
scp -O dist/fips_<version>_<arch>.apk root@192.168.1.1:/tmp/
ssh root@192.168.1.1 apk add --allow-untrusted /tmp/fips_<version>_<arch>.apk
```

On a router with no internet access, add `--no-network --repositories-file
/dev/null`, so apk does not try the package feeds:

```bash
apk add --allow-untrusted --no-network --repositories-file /dev/null \
  /tmp/fips_<version>_<arch>.apk
```

Without them apk prints an error for each feed it cannot fetch, and
`--no-network` alone still warns once per feed with no cached index. apk then
cannot fetch the package's dependencies (`kmod-tun`, `kmod-br-netfilter`,
`kmod-nft-nat`, `kmod-nf-conntrack`, `ip-full`), so they must already be
installed.

On OpenWrt 25.x, installing from a *signed repository* requires the publisher's
key; a single `--allow-untrusted` package install does not. If we ever publish an
apk feed, add ECDSA (prime256v1) signing via `apk mkpkg --sign` and distribute the
public key to `/etc/apk/keys/`.

## Upgrading

Upgrade with the same command, pointed at the new package:

```bash
ssh root@192.168.1.1 apk add --allow-untrusted /tmp/fips_<new-version>_<arch>.apk
```

On a router with no internet access, add `--no-network --repositories-file
/dev/null`, as for the install.

The new package's upgrade scripts stop `fips` and `fips-gateway` before the
files are replaced, then start `fips` again and start `fips-gateway` only if it
was enabled, so the upgrade keeps the gateway's enabled state. apk runs
the incoming package's upgrade scripts, not the installed one's, so this holds
from the first upgrade onto a package that carries them, whatever version is
installed.

`/etc/fips/fips.yaml` is marked as a config file (via
`/lib/apk/packages/fips.conffiles`), so apk preserves local edits across upgrades,
and `/lib/upgrade/keep.d/fips` preserves `/etc/fips/` across `sysupgrade` — the
same guarantees as the `.ipk` package.
