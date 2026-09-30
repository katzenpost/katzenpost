#!/bin/sh
# Run every TLC configuration of the mix server models and compare the result
# with what is expected. A configuration either must pass, or must fail on one
# named invariant (the counterexample is the point of it).
#
# Usage: ./check.sh
# Needs java, and tla2tools.jar in this directory or named by $TLA2TOOLS.

set -u
cd "$(dirname "$0")" || exit 1
JAR="${TLA2TOOLS:-$PWD/tla2tools.jar}"
if [ ! -f "$JAR" ]; then
    echo "tla2tools.jar not found; set TLA2TOOLS or download it from" >&2
    echo "https://github.com/tlaplus/tlaplus/releases" >&2
    exit 2
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
failed=0

# check <module> <config> <expected>, where <expected> is "pass" or an
# invariant name.
check() {
    mod="$1"; cfg="$2"; expected="$3"; log="$TMP/$mod.$cfg.log"
    java -XX:+UseParallelGC -jar "$JAR" -workers auto \
        -metadir "$TMP/$mod.$cfg.states" \
        -config "${mod}_$cfg.cfg" "$mod.tla" >"$log" 2>&1
    if grep -q "Model checking completed. No error has been found." "$log"; then
        got="pass"
    else
        got="$(sed -n 's/^Error: Invariant \(.*\) is violated\.$/\1/p' "$log" | head -n 1)"
        [ -n "$got" ] || got="error"
    fi
    states="$(sed -n 's/^\([0-9]*\) states generated, \([0-9]*\) distinct states found.*/\2/p' "$log" | tail -n 1)"
    if [ "$got" = "$expected" ]; then
        printf 'ok    %-8s %-17s %-20s %s distinct states\n' "$mod" "$cfg" "$got" "$states"
    else
        printf 'FAIL  %-8s %-17s expected %s, got %s\n' "$mod" "$cfg" "$expected" "$got"
        [ "$got" = "error" ] && tail -n 20 "$log"
        failed=1
    fi
}

check MixNode Pipeline         pass
check MixNode WitnessSent      NeverSent
check MixNode WitnessDelivered NeverDelivered
check MixNode WitnessShortened NeverShortened
check MixKeys Healthy          pass
check MixKeys OneSkip          pass
check MixKeys OneSkipSecrecy   KeysDestroyedOnTime
check MixKeys TwoSkips         KeysAvailable
check MixKeys Restart          pass
check MixKeys RestartReplay    ReplayFreedom
check MixKeys RestartSecrecy   KeysDestroyedOnTime
check MixKeys WitnessAccepts   NeverAccepts
check MixKeys WitnessDestroys  NeverDestroys

exit $failed
