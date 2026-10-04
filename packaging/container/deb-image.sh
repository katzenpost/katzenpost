#!/bin/sh
set -eu

mode=ref
case ${1:-} in
    --ref) mode=ref; shift ;;
    --ensure) mode=ensure; shift ;;
    --push) mode=push; shift ;;
esac
distro=${1:-debian-13}
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
podman=${PODMAN:-podman}
base=docker.io/$(printf '%s' "$distro" | sed 's/-/:/')
name=${DEB_IMAGE_NAME:-ghcr.io/katzenpost/katzenpost/deb-build}

sum=$(sha256sum < "$root/packaging/container/Containerfile.ci")
tag=$(printf '%s' "${sum%% *}" | cut -c1-12)
ref=$name:$distro-$tag

if [ "$mode" = ref ]; then
    printf '%s\n' "$ref"
    exit 0
fi

if "$podman" manifest inspect "$ref" >/dev/null 2>&1; then
    printf '%s\n' "$ref exists; not rebuilding"
    exit 0
fi

"$podman" build -f "$root/packaging/container/Containerfile.ci" \
    --build-arg "BASE=$base" -t "$ref" "$root"
if [ "$mode" = push ]; then
    "$podman" push "$ref"
fi
