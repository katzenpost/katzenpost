#!/bin/sh
# Run every TLC configuration of the voting-authority model and compare the
# result with what is expected. A configuration either must pass, or must
# fail on one named invariant (the counterexample is the point of it).
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

# check <config> <expected>, where <expected> is "pass" or an invariant name.
check() {
    cfg="$1"; expected="$2"; log="$TMP/$cfg.log"
    java -XX:+UseParallelGC -jar "$JAR" -workers auto \
        -metadir "$TMP/$cfg.states" \
        -config "VotingAuthority_$cfg.cfg" VotingAuthority.tla >"$log" 2>&1
    if grep -q "Model checking completed. No error has been found." "$log"; then
        got="pass"
    else
        got="$(sed -n 's/^Error: Invariant \(.*\) is violated\.$/\1/p' "$log" | head -n 1)"
        [ -n "$got" ] || got="error"
    fi
    states="$(sed -n 's/^\([0-9]*\) states generated, \([0-9]*\) distinct states found.*/\2/p' "$log" | tail -n 1)"
    if [ "$got" = "$expected" ]; then
        printf 'ok    %-20s %-30s %s distinct states\n' "$cfg" "$got" "$states"
    else
        printf 'FAIL  %-20s expected %s, got %s\n' "$cfg" "$expected" "$got"
        [ "$got" = "error" ] && tail -n 20 "$log"
        failed=1
    fi
}

check Honest              pass
check Epochs              pass
check ByzantineValidity   pass
check Byzantine4          pass
check Byzantine           Agreement
check Byzantine5          Agreement
check Byzantine6          Agreement
check EpochsByzantine     ChainConsistency
check Equivocation        ConvergenceUnderFullDelivery
check Shape               ConvergenceUnderFullDelivery
check ShapeMinTwo         ConvergenceUnderFullDelivery
check WitnessConsensus    ConsensusUnreachable
check WitnessChainRestart ChainUnanimity

exit $failed
