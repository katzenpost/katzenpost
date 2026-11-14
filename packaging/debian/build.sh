#!/bin/sh
set -eu

cd "$(dirname "$0")/../.."
dpkg-buildpackage -b -uc -us -d "$@"
mkdir -p dist
mv ../katzenpost_*.deb ../kpclientd_*.deb dist/
sha256sum dist/*.deb
