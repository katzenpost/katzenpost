#!/bin/sh
# Install the single katzenpost package of an earlier release, edit a
# conffile, then upgrade to the kpclientd and katzenpost packages in dist/.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
ref=${1:-v0.0.110}
old=${TMPDIR:-/tmp}/upgrade-old
mark='# edited before the upgrade'

rm -rf "$old"
mkdir -p "$old/src"
git -c safe.directory='*' -C "$root" archive "$ref" | tar -x -C "$old/src"
(cd "$old/src" && dpkg-buildpackage -b -uc -us -d >/dev/null)

apt install -y "$old"/katzenpost_*.deb
test "$(dpkg-query -S /usr/bin/kpclientd | cut -d: -f1)" = katzenpost
printf '%s\n' "$mark" >> /etc/katzenpost/kpclientd.toml

apt install -y "$root"/dist/katzenpost_*.deb "$root"/dist/kpclientd_*.deb
dpkg-query -W katzenpost kpclientd
"$root/packaging/debian/test.sh"
grep -qx "$mark" /etc/katzenpost/kpclientd.toml \
    || { printf '%s\n' "the upgrade lost an edited conffile" >&2; exit 1; }
rm -rf "$old"
