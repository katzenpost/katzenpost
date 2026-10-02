#!/bin/sh
# Run every TLC configuration of every model and compare each verdict with the
# expected one. A configuration either passes, or fails on one named invariant,
# the counterexample being the point of it.
#
# Needs java and tla2tools.jar: $TLA2TOOLS, or tla2tools.jar at the repository
# root. `make tla` fetches a pinned release, checks its digest and calls this.
#
# The manifest at the end is "directory module configuration expected-verdict
# [workers]". Workers defaults to auto; a configuration names a number where
# more workers make it slower, which happens when generating initial states
# dominates the run.

set -u
cd "$(dirname "$0")/.." || exit 1
JAR="${TLA2TOOLS:-$PWD/tla2tools.jar}"
case "$JAR" in /*) ;; *) JAR="$PWD/$JAR" ;; esac
if [ ! -f "$JAR" ]; then
    echo "tla2tools.jar not found; run 'make tla-tools' or set TLA2TOOLS" >&2
    exit 2
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
failed=0

while read -r dir mod cfg expected workers; do
    [ -n "${dir:-}" ] || continue
    : "${workers:=auto}"
    log="$TMP/$mod.$cfg.log"
    ( cd "$dir" && java -XX:+UseParallelGC -jar "$JAR" -workers "$workers" \
        -metadir "$TMP/$mod.$cfg.states" \
        -config "${mod}_$cfg.cfg" "$mod.tla" ) >"$log" 2>&1
    if grep -q "Model checking completed. No error has been found." "$log"; then
        got="pass"
    else
        got="$(sed -n 's/^Error: Invariant \(.*\) is violated\.$/\1/p' "$log" | head -n 1)"
        [ -n "$got" ] || got="error"
    fi
    states="$(sed -n 's/^[0-9]* states generated, \([0-9]*\) distinct states found.*/\1/p' "$log" | tail -n 1)"
    if [ "$got" = "$expected" ]; then
        printf 'ok    %-15s %-18s %-28s %s distinct states\n' "$mod" "$cfg" "$got" "$states"
    else
        printf 'FAIL  %-15s %-18s expected %s, got %s\n' "$mod" "$cfg" "$expected" "$got"
        [ "$got" = "error" ] && tail -n 20 "$log"
        failed=1
    fi
done <<'MANIFEST'
authority/voting/tla VotingAuthority Honest              pass
authority/voting/tla VotingAuthority Epochs              pass
authority/voting/tla VotingAuthority ByzantineValidity   pass
authority/voting/tla VotingAuthority Byzantine4          pass
authority/voting/tla VotingAuthority Byzantine           Agreement
authority/voting/tla VotingAuthority Byzantine5          Agreement
authority/voting/tla VotingAuthority Byzantine6          Agreement
authority/voting/tla VotingAuthority EpochsByzantine     ChainConsistency
authority/voting/tla VotingAuthority Equivocation        ConvergenceUnderFullDelivery
authority/voting/tla VotingAuthority Shape               AllOrNoneUnderFullDelivery
authority/voting/tla VotingAuthority ShapeSafety         pass
authority/voting/tla VotingAuthority Namenlos            NoHonestLeftOut              4
authority/voting/tla VotingAuthority NamenlosShards      ShardableUnderFullDelivery   4
authority/voting/tla VotingAuthority NamenlosServices    pass                         4
authority/voting/tla VotingAuthority WitnessConsensus    ConsensusUnreachable
authority/voting/tla VotingAuthority WitnessChainRestart ChainUnanimity
client/tla           ClientARQ       Sequential          pass
client/tla           ClientARQ       Concurrent          pass
client/tla           ClientARQ       Disconnect          pass
client/tla           ClientARQ       WitnessCompletes    NeverCompletes
client/tla           ClientARQ       WitnessStale        NeverStale
server/tla           MixNode         Pipeline            pass
server/tla           MixNode         WitnessSent         NeverSent
server/tla           MixNode         WitnessDelivered    NeverDelivered
server/tla           MixNode         WitnessShortened    NeverShortened
server/tla           MixKeys         Healthy             pass
server/tla           MixKeys         OneSkip             pass
server/tla           MixKeys         TwoSkips            pass
server/tla           MixKeys         Restart             pass
server/tla           MixKeys         RestartReplay       ReplayFreedom
server/tla           MixKeys         RestartSecrecy      KeysDestroyedOnTime
server/tla           MixKeys         WitnessAccepts      NeverAccepts
server/tla           MixKeys         WitnessDestroys     NeverDestroys
MANIFEST

exit $failed
