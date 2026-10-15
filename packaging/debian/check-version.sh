#!/bin/sh
set -eu

changelog=$1
tag=${2-}

die() {
    printf '%s\n' "$*" >&2
    exit 1
}

top=$(sed -n '1s/^[^ ]* (\([^)]*\)).*/\1/p' "$changelog")
test -n "$top" || die "$changelog: no version on the first line"

if [ -n "$tag" ]; then
    case $tag in
    v*) ;;
    *) die "tag $tag does not start with v" ;;
    esac
    test "$top" = "${tag#v}" \
        || die "$changelog: top version $top does not match tag $tag"
    exit 0
fi

latest=$(git describe --tags --abbrev=0 --match 'v*.*.*')
oldest=$(printf '%s\n%s\n' "$top" "${latest#v}" | sort -V | head -n 1)
test "$oldest" = "${latest#v}" \
    || die "$changelog: top version $top is older than tag $latest"
