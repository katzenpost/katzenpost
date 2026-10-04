#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
debs=${DEBS_DIR:-/tmp/debs}
go_version=${GO_VERSION:-1.27.1}
go_sum=63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445
GO_SHA256=${GO_SHA256:-$go_sum}
mkdir -p "$debs"
cd "$root"

need_tools=
for tool in dpkg-buildpackage dh curl git ping; do
    command -v "$tool" >/dev/null || need_tools=1
done
if [ -n "$need_tools" ]; then
    apt update
    apt install -y --no-install-recommends \
        build-essential debhelper dpkg-dev \
        ca-certificates curl git \
        iputils-ping systemd
fi

if ! /usr/local/go/bin/go version 2>/dev/null | grep -q "go$go_version"; then
    arch=$(dpkg --print-architecture)
    curl -fsSLo /tmp/go.tar.gz \
        "https://go.dev/dl/go${go_version}.linux-${arch}.tar.gz"
    echo "$GO_SHA256  /tmp/go.tar.gz" | sha256sum -c -
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
fi
PATH=/usr/local/go/bin:$PATH
export PATH

"$root/packaging/debian/build.sh"
cp "$root"/dist/katzenpost_*.deb "$debs"/

apt update
apt install -y "$debs"/katzenpost_*.deb
"$root/packaging/debian/test.sh"
"$root/packaging/debian/assert-reproducible.sh"
