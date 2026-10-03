#!/bin/sh
set -eu

distro=${1:-debian-13}
image=$(printf '%s' "$distro" | tr '-' ':')
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
podman=${PODMAN:-podman}

"$podman" run --rm \
    --volume "$root":/src:z \
    --workdir /src \
    "$image" \
    sh -c 'packaging/debian/ci.sh'
