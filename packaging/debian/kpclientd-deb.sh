#!/bin/sh
# Build dist/kpclientd_<version>_<arch>.deb: the client daemon alone, with its
# configs and units, versioned from the top entry of debian/changelog.
set -eu
umask 022

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$root"

version=$(dpkg-parsechangelog -SVersion)
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(dpkg-parsechangelog -STimestamp)}
export SOURCE_DATE_EPOCH
arch=$(dpkg --print-architecture)

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
pkg=$stage/pkg

# kpclientd links C code (CTIDH, SPHINCS+), so it is built natively, not
# cross-compiled.
go build -trimpath -buildvcs=false -o "$stage/kpclientd" \
    -ldflags "-s -w -X github.com/katzenpost/katzenpost/common.BuildVersion=$version" \
    ./cmd/kpclientd

install -D -m0755 "$stage/kpclientd" "$pkg/usr/bin/kpclientd"
install -D -m0644 debian/kpclientd.toml "$pkg/etc/katzenpost/kpclientd.toml"
install -D -m0644 debian/thinclient.toml "$pkg/etc/katzenpost/thinclient.toml"
install -D -m0644 debian/katzenpost.kpclientd.service \
    "$pkg/usr/lib/systemd/system/kpclientd.service"
install -D -m0644 debian/katzenpost.kpclientd.user.service \
    "$pkg/usr/lib/systemd/user/kpclientd.service"
install -D -m0644 debian/copyright "$pkg/usr/share/doc/kpclientd/copyright"

# dpkg-shlibdeps reads debian/control, so it runs from the source root.
depends=$(dpkg-shlibdeps -O "$pkg/usr/bin/kpclientd" 2>/dev/null \
    | sed -n 's/^shlibs:Depends=//p')
size=$(du -sk "$pkg" | cut -f1)

mkdir "$pkg/DEBIAN"
cat > "$pkg/DEBIAN/control" <<EOF
Package: kpclientd
Version: $version
Architecture: $arch
Maintainer: Katzenpost <packages@katzenpost.network>
Installed-Size: $size
Depends: $depends
Conflicts: katzenpost
Section: net
Priority: optional
Homepage: https://katzenpost.network/
Description: Katzenpost thin client daemon
 kpclientd alone, for hosts that only run Katzenpost client applications.
 The katzenpost package ships the same daemon along with the servers and
 tools, so the two packages conflict.
 .
 It gets a system and a user unit, both shipped disabled and unstarted.
 kpclientd.toml and thinclient.toml in /etc/katzenpost hold no secrets
 and are conffiles; editing them points the daemon at another network.
EOF
printf '/etc/katzenpost/kpclientd.toml\n/etc/katzenpost/thinclient.toml\n' \
    > "$pkg/DEBIAN/conffiles"
cat > "$pkg/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = configure ] && [ -d /run/systemd/system ]; then
    systemctl --system daemon-reload >/dev/null || true
fi
EOF
chmod 0755 "$pkg/DEBIAN/postinst"

find "$pkg" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
mkdir -p dist
deb=dist/kpclientd_${version}_${arch}.deb
dpkg-deb --root-owner-group -Zxz --build "$pkg" "$deb"
sha256sum "$deb"
