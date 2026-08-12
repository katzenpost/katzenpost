# TLA+ model of the voting directory authority

A model of the consensus protocol in
[`authority/voting/server/state.go`](../server/state.go), as it is on `main` at
commit `51270d399a841cf88b442cde4b9a4a77094ce21b`.

## What is modelled

The real authority runs a timed finite-state machine over one epoch:

```
AcceptDescriptor -> AcceptVote -> AcceptReveal -> AcceptCert -> AcceptSignature
   (1/8)            (2/8)          (3/8)           (4/8)         (5/8)
```

`VotingAuthority.tla` abstracts it into three message rounds and an epoch
boundary: `vote`, each authority broadcasts its descriptor view and commitment;
`cert`, authorities exchange certificates and each computes a document; `sig`,
they exchange signatures and finalise at `Threshold`; then each picks the
shared-random value the next epoch chains on.

Each element follows a named function in `state.go`:

| Model element | Follows |
|---|---|
| `Threshold` is `floor(N/2) + 1` | `votingThresholds` |
| A certificate is accepted only from a peer whose vote arrived | `onCertUpload` |
| Only an authority holding `Threshold` votes issues one | `tallyVotes` |
| Descriptors are tallied over received votes, with no equivocation check | `tallyVotes` |
| Participants come from certificates; an authority seen with two commitments is excluded | `verifyCommits` |
| A document needs `Threshold` votes, certificates and consistent commitments, or the authority signs nothing | `getMyConsensus` |
| A tally must have the shape a configuration's `Topology` demands, to certify and to compute a document | `IsDocumentWellFormed`, at `getCertificate` and `getMyConsensus`; `verifyTopology` at `getMyConsensus` |
| An authority signs only its own document, and finalises at `Threshold` signatures over it | `getThresholdConsensus` |
| The prior epoch's value is hashed in, or zero bytes when absent | `computeSharedRandom` |
| An authority that did not finalise may be given any threshold-signed document, or none | `stateBootstrap` |

`Topology` is a set of node sets a document needs at least one node from each of:
one per mix layer, one for the gateways, one for the service nodes. Storage
replicas are not one, because `IsDocumentWellFormed` checks each replica
descriptor and never counts them. A shared-random value is modelled as the chain
of `(epoch, participants)` links it came from, so values with different histories
differ. Delivery is lossy throughout: each authority receives from an arbitrary
subset.

## What is not modelled

A property that holds here is established only up to these gaps.

- **Rounds are synchronous**, where real authorities can be in different phases,
  or epochs, at once.
- **One value stands for a vote's descriptors and its commitment**, so a
  Byzantine authority equivocates on both at once; varying descriptors under a
  single commitment is not explored. No checked invariant depends on who is
  excluded from the shared random.
- **The reveal round is folded into the vote round**, so a reveal cannot be lost
  alone. In `state.go` it can, and `getCertificate` then omits that authority
  from the commitments while still counting its vote.
- **Byzantine certificates are uniform**: an arbitrary set of votes, the same set
  to everyone.
- **Mix parameters and the Sphinx geometry**, neither being a condition on
  agreement. `TestOneByzantineAuthorityCannotStallOrFork` covers a differing
  parameter block.
- **Weekly rotation of `PriorSharedRandom`.**
- **The ascending identity-hash walk and blaming only a certificate's author.**
  Exclusion here is equivocation alone, so the model neither exercises those
  rules nor depends on them.
- **Liveness**, since only invariants are checked and there is no fairness
  condition.
- **Cryptography**, which is symbolic.
- **Realistic node counts**, the search growing as `2^|Nodes|` per authority. The
  network this follows is namenlos, whose consensus is published at
  <https://status.namenlos.network/>: six authorities, three mix layers of two,
  two and three mixes, five gateways in the consensus, four service nodes, four
  storage replicas.
- **Storage replicas**, except in the three `Namenlos` configurations. A
  conforming deployment runs at least four (`pigeonhole.md`) and sharding
  addresses `K` per envelope (`replica/common/shard.go`), but neither is a
  condition on a consensus, so an authority signs a document that leaves an
  envelope unreachable and the pigeonhole path is what fails.

The model assumes `Cardinality(Byzantine) < Threshold`. Byzantine authorities
sign only documents an honest authority computed, which loses nothing under that
assumption: a document they invent gathers at most `Cardinality(Byzantine)`
signatures.

## Properties

| Invariant | Statement |
|---|---|
| `TypeOK` | Type invariant. |
| `Agreement` | No two honest authorities finalise different documents. |
| `UniqueConsensus` | At most one document per epoch holds `Threshold` signatures. |
| `DescriptorValidity` | Every descriptor in an honest document was in some honest view. |
| `ChainConsistency` | Honest authorities chaining onto a prior document chain onto the same one. |
| `ChainGrounded` | A chain is consecutive epochs ending at the previous one. |
| `ConvergenceUnderFullDelivery` | With full delivery and a common prior, honest documents are equal. |
| `AllOrNone` | Either every honest authority computed a document, or none did. |
| `AllOrNoneUnderFullDelivery` | `AllOrNone`, with nothing lost and a common prior. |
| `NoHonestLeftOut` | `AllOrNone`, when every honest authority's own view is well formed too. |
| `ShardableUnderFullDelivery` | Fewer than `K` replicas are missing, so every envelope keeps a shard. |
| `ServicesSurviveUnderFullDelivery` | Some node advertising each service survives the tally. |

`UniqueConsensus` is stronger than `Agreement`: it also covers a threshold-signed
document no honest authority finalised, which a Byzantine authority could still
serve to a client or a bootstrapping peer.

Two are checked only to obtain a witness trace and so are expected to fail:
`ConsensusUnreachable`, whose counterexample is a successful consensus, and
`ChainUnanimity`, whose counterexample is honest authorities entering an epoch on
different priors. `Validity`, `Integrity` and the claim that every shared-random
value has an honest contributor are tautologies under this encoding and are not
checked; the comment at the end of the `.tla` says why for each.

## Why a majority threshold is not enough

Two quorums of size `Threshold` overlap in `2*Threshold - N` authorities, and
agreement survives `f` Byzantine authorities only while that overlap exceeds
`f`. For a majority threshold the overlap is 2 at every even `N` and 1 at every
odd `N`, so it tolerates one fault at even `N`, none at odd `N`, and two at no
`N` at all. Adding authorities does not raise the tolerance; only a threshold
above the majority does.

| N | Threshold | Overlap | f = 1 | f = 2 | Checked by |
|---|---|---|---|---|---|
| 3 | 2 | 1 | no | no | `Byzantine` |
| 4 | 3 | 2 | yes | no | `Byzantine4` |
| 5 | 3 | 1 | no | no | `Byzantine5` |
| 6 | 4 | 2 | yes | no | `Byzantine6` at `f` = 2 |

No six-authority configuration asserts that `Agreement` holds against one fault:
six authorities cannot be searched exhaustively, and `MinimalVoteChoices` must
not be used to argue that an invariant holds. The arithmetic gives that result
and `Byzantine4` exhibits the mechanism at even `N`.

## Configurations

| Config | Auths | Byz | Nodes | Epochs | Expected | Distinct states |
|---|---|---|---|---|---|---|
| `Honest` | 3 | 0 | 2 | 1 | all hold | 152,062 |
| `Epochs` | 3 | 0 | 1 | 3 | all hold | 385,268 |
| `ByzantineValidity` | 3 | 1 | 1 | 2 | validity and chain shape hold | 688,980 |
| `Byzantine4` | 4 | 1 | 1 | 1 | all safety invariants hold | 6,100,574 |
| `Byzantine` | 3 | 1 | 1 | 1 | `Agreement` violated | |
| `Byzantine5` | 5 | 1 | 0 | 1 | `Agreement` violated | |
| `Byzantine6` | 6 | 2 | 0 | 1 | `Agreement` violated | |
| `EpochsByzantine` | 3 | 1 | 0 | 2 | `ChainConsistency` violated | |
| `Equivocation` | 4 | 1 | 1 | 1 | `ConvergenceUnderFullDelivery` violated | |
| `Shape` | 4 | 1 | 5 | 1 | `AllOrNoneUnderFullDelivery` violated | |
| `ShapeSafety` | 4 | 1 | 5 | 1 | all safety invariants hold | 3,741,466 |
| `Namenlos` | 4 | 1 | 20 | 1 | `NoHonestLeftOut` violated | |
| `NamenlosShards` | 4 | 1 | 20 | 1 | `ShardableUnderFullDelivery` violated | |
| `NamenlosServices` | 4 | 1 | 20 | 1 | five hold | 89,580 |
| `WitnessConsensus` | 3 | 0 | 1 | 1 | `ConsensusUnreachable` violated | |
| `WitnessChainRestart` | 3 | 0 | 0 | 2 | `ChainUnanimity` violated | |

Each file is `VotingAuthority_<Config>.cfg` and says in its own comment what its
result shows. Counts are from TLC 2.19, the release `make tla` pins. A failing
configuration has no stable count, because TLC stops at the first counterexample
its workers reach and which one that is varies between runs of an unchanged tree.

`Shape` is the shape gate at the smallest shape that can trip it. One Byzantine
authority sends a service node to two honest authorities and withholds it from
the third, which leaves that one below threshold on it, so its service-node group
is empty, it issues no certificate and holds no document while the other two hold
one. It checked `ConvergenceUnderFullDelivery` until that was found to be the
wrong witness: with singleton groups one node missing from every honest view
makes every tally malformed, so that invariant fails there with no adversary at
all. `AllOrNoneUnderFullDelivery` found no counterexample without one, but under
`MinimalVoteAssignments`, so that run establishes nothing either.

`Namenlos` is the same gate at the deployed shape, with the nodes, groups and
service advertisements the published consensus shows at
<https://status.namenlos.network/>: three mix layers of two, two and three; five
gateways; four service nodes, three advertising a courier and all four an echo;
four storage replicas. Four authorities rather than six, so the threshold is 3 of
4 where the network's is 4 of 6.

Storage replicas are not a `Topology` group, and in the model they are exactly the
descriptors in no group, which is the same fact: `IsDocumentWellFormed` checks each
replica descriptor and never counts them. They are tallied like every other
descriptor, so they are contestable. A courier is not a role either; it runs on a
service node and is advertised through that node's Kaetzchen map, so a service is
the set of nodes offering it.

Every group has a spare, so no single disputed descriptor can empty one, and
emptying the thinnest takes two: in the trace a1 and a2 hold one node of a
two-node layer and a3 holds the other, so every honest view is still well formed,
and the Byzantine authority withholds both from a1 alone. Each sits below
threshold there, a1's layer is empty and it issues no certificate, while the other
two certify and hold a document. The round still succeeds without a1, so what this
shows is one authority excluded rather than a consensus prevented.

`NamenlosShards` and `NamenlosServices` ask the same shape what a consensus owes
its consumers rather than its signers. Each has its own file because TLC stops at
the first counterexample, so a configuration decides one claim.

Sharding has no margin at all. `GetShards` addresses `K` of the four configured
replicas per envelope and then drops the ones the document omits, so an envelope
is unreachable as soon as all `K` of its shards are missing, and with `K` of two
a two-descriptor dispute is enough. `NamenlosShards` exhibits it. The services
claim holds over an exhaustive search of the restricted specification: three
nodes advertise a courier and four an echo, so one contested pair cannot empty
either. Both are provisioning margins rather than guarantees, because
`getMyConsensus` checks neither, and the authorities sign such a document without
noticing.

None of this is established at these node counts, because delivery is pinned to
full delivery and vote content to one contested set. It is what is reachable where
the network actually runs.

No configuration establishes a safety invariant with a non-empty `Topology`.
`Agreement`, `UniqueConsensus` and `DescriptorValidity` are established only where
`Topology` is empty, `Byzantine4` being the configuration that carries them
against a Byzantine authority and restricting nothing. The two that check them
with a non-empty `Topology`, `ShapeSafety` and `NamenlosServices`, both restrict
`VoteAssignments`, and a pass under a restriction establishes nothing.

`ShapeSafety` is `Shape`'s shape with those three invariants in place of the gate.
What it adds to `NamenlosServices` is delivery: it is the only configuration that
checks safety with a non-empty `Topology` and arbitrary loss, and it passes over
3,741,466 distinct states, fewer than `Byzantine4`'s 6,100,574 and `MixNode`
`Pipeline`'s 6,591,120. It needs `SYMMETRY` for that: without it the same search
is 22,055,812 distinct states.

Lifting the content restriction is what would establish those three at a
non-empty `Topology`, and the search does not permit it. `FullVoteAssignments`
draws a view from `SUBSET Nodes` for each honest authority and one per recipient
for each Byzantine one, so five nodes and four authorities of which one is
Byzantine give 32^3 * 32^4, which is 34,359,738,368 initial states before a
single round is taken. One node per group is the smallest non-empty `Topology`,
and three nodes with those authorities still give 8^3 * 8^4, which is 2,097,152,
against `Byzantine4`'s 128. What carries safety at
the deployed shape is the threshold arithmetic above and `Byzantine4`, not a
configuration at that shape.

`Epochs`, `ByzantineValidity`, `Byzantine4`, `Equivocation`, `ShapeSafety` and the
three `Namenlos` configurations set `SYMMETRY`, sound for them because no
invariant they check names a particular authority or node. Permuting nodes is not
sound with a non-empty `Topology`, which moves nodes between groups, so `Symmetry`
permutes nodes only where `Topology` is empty and permutes authorities either
way.

`Byzantine5` and `Byzantine6` substitute `MinimalVoteChoices` for `VoteChoices`,
restricting delivery to the smallest sets that still allow a document. Every run
of the restricted specification is a run of the full one, so a counterexample is
genuine; the same substitution must not be used to argue that an invariant holds.
That the restrictions are restrictions is checked rather than asserted: `ASSUME`s
state each subset claim, TLC evaluates them before searching, and inverting one
stops TLC with `Assumption ... is false`.

Each invariant expected to hold was mutation-tested, by introducing a deliberate
error into a copy of the specification and confirming TLC reported it violated.

## Running

`make tla` from the repository root fetches the pinned tla2tools through
`make tla-tools`, which checks its digest, and runs every configuration of every model through
[`.ci/tla.sh`](../../../.ci/tla.sh), comparing each verdict with the expected one
and exiting non-zero if any differs.

For one configuration and its trace, with the jar here or named by `TLA2TOOLS`:

```sh
java -jar tla2tools.jar -config VotingAuthority_Byzantine.cfg VotingAuthority.tla
```

Give each concurrent TLC its own `-metadir`, or they share a scratch directory
and one fails with a spurious parse error. Five authorities need
`-maxSetSize 3000000`, since the vote round alone exceeds TLC's default limit on
an enumerated set.
