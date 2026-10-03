#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
a=$(sha256sum "$root"/dist/*.deb | awk '{print $1}' | sort \
    | sha256sum | cut -d' ' -f1)

rm -rf /tmp/rb
cp -a "$root" /tmp/rb
cd /tmp/rb
rm -rf dist
packaging/debian/build.sh
b=$(sha256sum /tmp/rb/dist/*.deb | awk '{print $1}' | sort \
    | sha256sum | cut -d' ' -f1)

printf 'first  %s\nsecond %s\n' "$a" "$b"
test "$a" = "$b"
