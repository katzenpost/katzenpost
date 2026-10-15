#!/bin/sh
set -eu

script=$(cd "$(dirname "$0")" && pwd)/check-version.sh
root=$(mktemp -d "${TMPDIR:-/var/tmp}/check-version-test.XXXXXX")
trap 'rm -rf "$root"' EXIT
failed=0
n=0

g() {
    git -c user.name=test -c user.email=test@example.invalid \
        -c init.defaultBranch=main -c core.hooksPath=/dev/null "$@"
}

repo() {
    n=$((n + 1))
    dir=$root/$n
    mkdir "$dir"
    g -C "$dir" init -q
    g -C "$dir" commit -q --allow-empty -m one
}

tag() {
    g -C "$dir" tag -a -m "$1" "$1"
}

changelog() {
    date='Thu, 15 Oct 2026 12:00:00 +0200'
    printf '%s\n' \
        "katzenpost ($1) unstable; urgency=medium" \
        '' \
        '  * Entry.' \
        '' \
        " -- Katzenpost <packages@katzenpost.network>  $date" \
        > "$dir/changelog"
}

expect() {
    want=$1
    name=$2
    shift 2
    if (cd "$dir" && sh "$script" changelog "$@") >"$dir/out" 2>&1; then
        got=pass
    else
        got=fail
    fi
    if [ "$got" = "$want" ]; then
        printf 'ok   %s\n' "$name"
    else
        printf 'FAIL %s: want %s, got %s\n' "$name" "$want" "$got"
        sed 's/^/     /' "$dir/out"
        failed=1
    fi
}

repo; tag v0.0.5; changelog 0.0.5
expect pass "branch: changelog equals the latest tag"

repo; tag v0.0.5; changelog 0.0.6
expect pass "branch: changelog newer than the latest tag"

repo; tag v0.0.5; changelog 0.0.4
expect fail "branch: changelog older than the latest tag"

repo; tag v0.0.9; changelog 0.0.10
expect pass "branch: versions compare numerically, not as text"

repo; tag v0.0.10; changelog 0.0.9
expect fail "branch: 0.0.9 is older than v0.0.10"

repo; tag v0.0.4; g -C "$dir" commit -q --allow-empty -m two; tag v0.0.5
changelog 0.0.5
expect pass "branch: the nearest tag is the latest"

repo; tag v0.0.5; g -C "$dir" checkout -q -b side
g -C "$dir" commit -q --allow-empty -m side; tag v0.0.9
g -C "$dir" checkout -q main; changelog 0.0.5
expect pass "branch: a tag not reachable from HEAD is ignored"

repo; tag v0.0.5; g -C "$dir" tag -a -m other other-9; changelog 0.0.5
expect pass "branch: tags not matching v*.*.* are ignored"

repo; changelog 0.0.5
expect fail "branch: no reachable v* tag"

repo; tag v0.0.5
expect fail "branch: no changelog"

repo; tag v0.0.5; printf 'not a changelog\n' > "$dir/changelog"
expect fail "branch: no version on the first line"

repo; changelog 0.0.7
expect pass "tag: changelog equals the tag" v0.0.7

repo; changelog 0.0.6
expect fail "tag: changelog older than the tag" v0.0.7

repo; changelog 0.0.8
expect fail "tag: changelog newer than the tag" v0.0.7

repo; changelog 0.0.7
expect fail "tag: tag missing its leading v" 0.0.7

exit $failed
