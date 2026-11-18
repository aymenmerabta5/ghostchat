#!/usr/bin/env bash
# Builds the Debian package from a finished dist/linux folder.
#
#   packaging/linux/build-deb.sh
#   packaging/linux/build-deb.sh --dist dist/linux --out dist --version 0.1.0
#
# The dist folder must contain `ghostchat`, `ghostchat.json` and
# `THIRD-PARTY-NOTICES.txt`; `cargo run -p ghostchat-xtask -- dist
# target/release/ghostchat dist/linux` writes exactly that.
#
# Needs dpkg-deb and dpkg-shlibdeps (the dpkg-dev package on Debian/Ubuntu).
# The package installs /usr/bin/ghostchat, the desktop entry, the 256 px icon,
# a systemd user unit for `ghostchat --relay`, and the license/provenance docs.
# Keys and settings stay in the user's own data directory and survive
# `apt remove`.
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
dist="$repo/dist/linux"
out="$repo/dist"
version=""

die() {
    echo "build-deb: $*" >&2
    exit 1
}

usage() {
    sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dist)
            [ $# -ge 2 ] || die "--dist needs a directory"
            dist=$2
            shift 2
            ;;
        --out)
            [ $# -ge 2 ] || die "--out needs a directory"
            out=$2
            shift 2
            ;;
        --version)
            [ $# -ge 2 ] || die "--version needs a version"
            version=$2
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1 (try --help)"
            ;;
    esac
done

[ -x "$dist/ghostchat" ] || die "no executable ghostchat in $dist; build the dist folder first"
[ -f "$dist/ghostchat.json" ] || die "no ghostchat.json in $dist; build the dist folder first"
[ -f "$dist/THIRD-PARTY-NOTICES.txt" ] || die "no THIRD-PARTY-NOTICES.txt in $dist"
command -v dpkg-deb >/dev/null 2>&1 || die "dpkg-deb is missing; install dpkg-dev"
command -v dpkg-shlibdeps >/dev/null 2>&1 || die "dpkg-shlibdeps is missing; install dpkg-dev"

if [ -z "$version" ]; then
    version=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$dist/ghostchat.json" | head -n 1)
fi
version=${version#v}
[ -n "$version" ] || die "could not read the version from $dist/ghostchat.json; pass --version"
case "$version" in
    *[!0-9.]* | .* | *.) die "package version '$version' is not numeric" ;;
esac

arch=$(dpkg --print-architecture)
mkdir -p "$out"
out=$(cd "$out" && pwd)
output="$out/ghostchat_${version}_${arch}.deb"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
pkg="$work/ghostchat"

# Files, in the layout Debian expects.
install -Dm755 "$dist/ghostchat" "$pkg/usr/bin/ghostchat"
install -Dm644 "$repo/packaging/linux/ghostchat.desktop" "$pkg/usr/share/applications/ghostchat.desktop"
install -Dm644 "$repo/assets/ghostchat-256.png" "$pkg/usr/share/icons/hicolor/256x256/apps/ghostchat.png"
install -Dm644 "$repo/packaging/linux/ghostchat-relay.service" \
    "$pkg/usr/lib/systemd/user/ghostchat-relay.service"
install -Dm644 "$repo/packaging/linux/copyright" "$pkg/usr/share/doc/ghostchat/copyright"
install -Dm644 "$repo/LICENSE" "$pkg/usr/share/doc/ghostchat/LICENSE"
install -Dm644 "$repo/NOTICE" "$pkg/usr/share/doc/ghostchat/NOTICE"
install -Dm644 "$dist/THIRD-PARTY-NOTICES.txt" "$pkg/usr/share/doc/ghostchat/THIRD-PARTY-NOTICES.txt"
install -Dm644 "$dist/ghostchat.json" "$pkg/usr/share/doc/ghostchat/ghostchat.json"

# Shared-library dependencies come from the linked binary, not a guess.
mkdir -p "$work/shlibs/debian"
printf 'Source: ghostchat\n\nPackage: ghostchat\nArchitecture: any\n' > "$work/shlibs/debian/control"
depends=$(cd "$work/shlibs" && dpkg-shlibdeps -O "$pkg/usr/bin/ghostchat" 2>"$work/shlibs.log" | sed -n 's/^shlibs:Depends=//p')
if [ -z "$depends" ]; then
    cat "$work/shlibs.log" >&2
    die "dpkg-shlibdeps found no shared-library dependencies"
fi

installed_size=$(du -sk "$pkg/usr" | cut -f1)
mkdir -p "$pkg/DEBIAN"

# A Debian changelog entry, dated at build time. CHANGELOG.md is the human log;
# this is the package-manager record.
{
    printf 'ghostchat (%s) unstable; urgency=medium\n\n' "$version"
    printf '  * Release %s.\n\n' "$version"
    printf ' -- Aimen Merabta <aymenmerabta5@gmail.com>  %s\n' "$(date -Ru)"
} | gzip -9n > "$pkg/usr/share/doc/ghostchat/changelog.gz"
chmod 644 "$pkg/usr/share/doc/ghostchat/changelog.gz"

cat > "$pkg/DEBIAN/control" <<EOF
Package: ghostchat
Version: $version
Architecture: $arch
Maintainer: Aimen Merabta <aymenmerabta5@gmail.com>
Installed-Size: $installed_size
Depends: $depends
Recommends: bluez
Section: net
Priority: optional
Homepage: https://github.com/aymenmerabta5/ghostchat
Description: Private chat over the bitchat Bluetooth mesh
 ghostchat is a desktop client for the bitchat mesh for Windows and Linux.
 It talks to the bitchat apps over Bluetooth Low Energy and adds a private
 group chat that interoperates with the iOS reference implementation.
 .
 Closing the window keeps ghostchat in the notification area; quit from the
 tray icon to stop it. Keys and settings stay under the user's data
 directory and survive package removal.
EOF
chmod 644 "$pkg/DEBIAN/control"

(cd "$pkg" && find usr -type f -print0 | sort -z | xargs -0 md5sum) > "$pkg/DEBIAN/md5sums"
chmod 644 "$pkg/DEBIAN/md5sums"

rm -f "$output"
dpkg-deb --root-owner-group -Zxz --build "$pkg" "$output" >/dev/null

echo "package: $output"
dpkg-deb --field "$output" Package Version Architecture Depends Installed-Size
