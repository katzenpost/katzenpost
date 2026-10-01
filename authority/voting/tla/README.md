# TLA+ model of the voting directory authority

A formal model of the Katzenpost voting directory-authority consensus
protocol implemented in
[`authority/voting/server/state.go`](../server/state.go), as it is on `main`
at commit `91debb674`.

## What is modelled

The real authority runs a timed finite-state machine over one epoch:

```
AcceptDescriptor -> AcceptVote -> AcceptReveal -> AcceptCert -> AcceptSignature
   (1/8)            (2/8)          (3/8)           (4/8)         (5/8)
```

`VotingAuthority.tla` abstracts the timed FSM into three message-exchange
rounds, followed by an epoch boundary:

| Step           | Models                                                                 |
|----------------|------------------------------------------------------------------------|
| `vote`         | Each authority broadcasts its vote (descriptor view + SR commitment).  |
| `cert`         | Authorities exchange certificates and each computes a document.        |
| `sig`          | Authorities exchange signatures; a doc is finalised at `Threshold`.    |
| epoch boundary | Each authority picks the shared-random value the next epoch chains on. |

Elements that follow `state.go`:

- **Threshold** is `floor(N/2) + 1`, as `votingThresholds()` computes it.
- **Certificates are accepted only from a peer whose vote was received**, as
  `onCertUpload()` requires, and only an authority holding `Threshold` votes
  issues one, as `tallyVotes()` requires.
- **Descriptors are tallied over directly received votes**, with no
  equivocation check, as in `tallyVotes()`.
- **Shared-random participants are gathered from certificates**, and an
  authority seen with two different commitments is excluded, as in
  `verifyCommits()`.
- **No document without a quorum.** An authority computes a document only if
  it holds `Threshold` votes, `Threshold` certificates and `Threshold`
  consistent commitments, as `getMyConsensus()` requires. Otherwise it signs
  nothing.
- **A document must have the shape `IsDocumentWellFormed` demands**, when a
  configuration asks for one. `MixLayers` is one node set per mix layer and a
  document needs `MinPerLayer` of each; `RoleGroups` is one set for the gateways
  and one for the service nodes, of which it needs at least one each. An
  authority whose tally leaves any of them short computes no document, because
  `getMyConsensus()` refuses to sign a malformed one and returns an error.
  Storage replicas are neither, because that function checks each replica
  descriptor and never counts them. Only `Shape` and `ShapeMinTwo` set these;
  with them empty both conditions are vacuous.
- **Threshold signatures.** An honest authority signs only its own document,
  and finalises it only with `Threshold` signatures over that exact document,
  as in `getThresholdConsensus()`.
- **Lossy delivery.** In every round each authority receives messages from an
  arbitrary subset of authorities.
- **Shared-random chaining.** `computeSharedRandom()` hashes in the previous
  epoch's value, or 32 zero bytes if `s.documents[epoch-1]` is absent. A
  shared-random value is modelled as the chain of `(epoch, participants)` links
  it was derived from, so values with different histories are different.
- **Epoch boundary.** An authority that finalised chains onto its own document.
  One that did not goes through `stateBootstrap`: its
  `backgroundFetchConsensus()` may deliver any threshold-signed document a peer
  can serve, or may not land in time, in which case it restarts from the zero
  value.

## What is not modelled

A property that holds in the model is established only up to these gaps.

- **Rounds are synchronous.** Every authority is always in the same phase of
  the same epoch. The real authorities run independent timed FSMs and can be
  in different phases, or different epochs, at once.
- **One value stands for a vote's descriptors and its commitment.** A
  Byzantine authority that sends two different values equivocates on both at
  once. In `state.go` it could vary its descriptors under a single commitment
  and stay a shared-random participant everywhere. That behaviour is not
  explored. No checked invariant depends on who is excluded from the shared
  random, and the descriptor tally never excludes anyone.
- **The reveal round is folded into the vote round.** The model assumes an
  authority's reveal arrives wherever its vote arrives. In `state.go` the two
  are separate messages, and a reveal can be lost on its own.
  `getCertificate()` then leaves that authority out of the commitments it
  relays, and still counts its vote in the descriptor tally. So the set of
  contributors to the shared random can be smaller than the set of voters.
  The model does not explore that. Adding it would multiply the delivery
  choices, and the four-authority run would no longer finish.
- **Byzantine certificates are uniform.** A Byzantine certificate relays an
  arbitrary set of votes, but the same set to every recipient. Commitments are
  signed, so it cannot forge one for an honest peer. Sending different
  certificates to different recipients is possible in reality and is not
  explored.
- **Mix parameters.** The parameter tally in `tallyVotes()` is not modelled, and
  the rates themselves are outside what a model checker can say anything about:
  they govern how often a client sends and how long a packet waits, not whether
  a document is agreed. In namenlos all six authorities carry a byte-identical
  parameter block, so the tally has nothing to resolve; the Go test
  `TestOneByzantineAuthorityCannotStallOrFork` is what covers the case where one
  authority votes a different block.
- **The Sphinx geometry.** A mismatch is rejected by the nodes and clients that
  consume a consensus, not by the authorities that sign it, so it is not a
  condition on agreement and belongs with the conformance vectors.
- **Weekly rotation of `PriorSharedRandom`** is not modelled.
- **Liveness.** Only invariants are checked. There is no fairness condition
  and no temporal property, so the model says nothing about whether consensus
  is eventually reached.
- **Cryptography is symbolic.** Signatures are unforgeable, and equal
  shared-random chains give equal values.
- **How many nodes there are.** `MixLayers` and `RoleGroups` fix which groups a
  document needs nodes from, and the two shape configurations use the smallest
  sets that keep the rule meaningful; the others leave them empty and model no
  document shape at all. Node counts
  are not a model-checking question: each authority's view is an arbitrary
  subset of `Nodes`, so the search grows as `2^|Nodes|` per authority and a
  realistic count is unreachable. The network this follows is namenlos, whose
  consensus is published at <https://status.namenlos.network/>: six
  authorities and so a threshold of four, three mix layers holding two, two and
  three mixes, four gateways, four service nodes and four storage replicas, on
  a topology pinned in the authority configuration rather than derived from the
  shared random. `Byzantine6` covers the authority count and `ShapeMinTwo` the
  two-mix layers; the remaining counts change nothing the model checks, because
  every property here turns on quorums and orderings and not on how many nodes
  a layer holds.
- **The minimum number of storage replicas.** Sharding needs two
  (`K` in `replica/common/shard.go`, enforced by `GetConfiguredReplicaKeys`),
  but that is a consumer of the consensus and not a condition on it:
  `IsDocumentWellFormed` checks each replica descriptor and never counts them,
  so an authority signs a document with one replica and the pigeonhole path is
  what fails. It is out of scope here.

The model also assumes `Cardinality(Byzantine) < Threshold`. Byzantine
authorities sign only documents that honest authorities computed, which loses
nothing under that assumption: a document they invent can gather at most
`Cardinality(Byzantine)` signatures.

## Properties

Expected to hold wherever the configuration table says so:

| Invariant                      | Statement                                                                 |
|--------------------------------|---------------------------------------------------------------------------|
| `TypeOK`                       | Type invariant.                                                           |
| `Agreement`                    | No two honest authorities finalise different documents.                   |
| `UniqueConsensus`              | At most one document per epoch holds `Threshold` signatures.              |
| `DescriptorValidity`           | Every descriptor in an honest document was in some honest view.           |
| `ChainConsistency`             | Honest authorities that chain onto a prior document chain onto the same.  |
| `ChainGrounded`                | A chain consists of consecutive epochs ending at the previous one.        |
| `ConvergenceUnderFullDelivery` | With full delivery and a common prior, honest documents are equal.        |

`UniqueConsensus` is stronger than `Agreement`. It also covers a
threshold-signed document that no honest authority finalised, but that a
Byzantine authority could still serve to a client or a bootstrapping peer.

Expected to fail, and checked only to obtain a witness trace:

| Invariant              | The counterexample is                                              |
|------------------------|--------------------------------------------------------------------|
| `ConsensusUnreachable` | a run in which every honest authority finalises the same document. |
| `ChainUnanimity`       | a run in which honest authorities enter an epoch on different priors. |

Three properties are deliberately not checked because they are tautologies
under this encoding: `Validity`, `Integrity`, and the claim that every
shared-random value has an honest contributor. The comment at the end of the
`.tla` explains each.

Each invariant that is expected to hold was mutation-tested: a deliberate
error was introduced into a copy of the specification, and TLC reported the
invariant violated.

| Mutation                                              | Invariant that caught it          |
|-------------------------------------------------------|-----------------------------------|
| `Threshold` lowered to `floor(N/2)`                   | `Agreement`, `UniqueConsensus`    |
| Descriptor tally threshold lowered to 1               | `DescriptorValidity`              |
| Failed epoch carries the old prior forward            | `ChainGrounded` (needs 3 epochs)  |
| Common-prior condition dropped from its premise       | `ConvergenceUnderFullDelivery`    |

## Configurations

| Config                | Auths | Byz | Nodes | Epochs | Expected result                       | Distinct states |
|-----------------------|-------|-----|-------|--------|---------------------------------------|-----------------|
| `Honest`              | 3     | 0   | 2     | 1      | all invariants hold                   | 152,062         |
| `Epochs`              | 3     | 0   | 1     | 3      | all invariants hold                   | 385,268         |
| `ByzantineValidity`   | 3     | 1   | 1     | 2      | validity and chain shape hold         | 688,980         |
| `Byzantine4`          | 4     | 1   | 1     | 1      | all safety invariants hold            | 6,100,574       |
| `Byzantine`           | 3     | 1   | 1     | 1      | `Agreement` violated                  |                 |
| `Byzantine5`          | 5     | 1   | 0     | 1      | `Agreement` violated                  |                 |
| `Byzantine6`          | 6     | 2   | 0     | 1      | `Agreement` violated                  |                 |
| `EpochsByzantine`     | 3     | 1   | 0     | 2      | `ChainConsistency` violated           |                 |
| `Equivocation`        | 4     | 1   | 1     | 1      | `ConvergenceUnderFullDelivery` violated |               |
| `Shape`               | 4     | 1   | 5     | 1      | `ConvergenceUnderFullDelivery` violated |               |
| `ShapeMinTwo`         | 4     | 1   | 6     | 1      | `ConvergenceUnderFullDelivery` violated |               |
| `WitnessConsensus`    | 3     | 0   | 1     | 1      | `ConsensusUnreachable` violated       |                 |
| `WitnessChainRestart` | 3     | 0   | 0     | 2      | `ChainUnanimity` violated             |                 |

Each file is named `VotingAuthority_<Config>.cfg`. State counts are from TLC
2.19. TLC stops at the first counterexample, so a failing configuration has no
meaningful count. Configurations marked `SYMMETRY` treat honest authorities,
Byzantine authorities and nodes as interchangeable.

`Byzantine5` is too large to search exhaustively. It substitutes
`MinimalVoteChoices` for `VoteChoices`, which restricts vote delivery to the
smallest sets that still allow a document. Every run of the restricted
specification is a run of the full one, so its counterexample is genuine. The
same substitution must not be used to argue that an invariant holds.

## Running

Requires Java and `tla2tools.jar` (TLC). Download it from
<https://github.com/tlaplus/tlaplus/releases> into this directory, or point
`TLA2TOOLS` at it. The jar is not committed.

```sh
./check.sh
```

runs every configuration and compares each result with the expected one. It
exits non-zero if any differs. The whole suite takes one to two minutes on a
12-core machine, most of it in `Byzantine4`.

To run one configuration and read its trace:

```sh
java -jar tla2tools.jar -config VotingAuthority_Byzantine.cfg VotingAuthority.tla
```

Do not run several TLC processes in this directory at once without giving
each its own `-metadir`. They share a scratch directory by default and one of
them fails with a spurious parse error.

## Interpreting the results

### Agreement needs more than a majority under Byzantine faults

With `N = 3` the threshold is `2`. In `Byzantine`, lossy delivery leaves the
two honest authorities with different views, so they compute different
documents. The Byzantine authority signs both, supplying the deciding second
signature for each. Both honest authorities finalise, on different documents.

The honest configurations pass under arbitrary message loss: omission and
crash faults alone never break agreement. Breaking it takes an authority that
signs two documents.

Two quorums of size `Threshold` overlap in at least `2*Threshold - N`
authorities. Agreement survives `f` Byzantine authorities when that overlap
exceeds `f`.

| N | Threshold | Overlap | Survives f = 1 | Survives f = 2 | Checked by                |
|---|-----------|---------|----------------|----------------|---------------------------|
| 3 | 2         | 1       | no             | no             | `Byzantine`               |
| 4 | 3         | 2       | yes            | no             | `Byzantine4`              |
| 5 | 3         | 1       | no             | no             | `Byzantine5`              |
| 6 | 4         | 2       | yes            | no             | `Byzantine6` (at `f` = 2) |

The overlap is `2*Threshold - N`, which for a majority threshold is 2 at every even
`N` and 1 at every odd `N`. So a majority threshold tolerates one Byzantine authority
at even `N`, none at odd `N`, and two at no `N` at all. Adding authorities does not
raise the tolerance; only a threshold above the majority does.

`Byzantine6` is the two-fault case at six authorities: four honest authorities split
into two pairs, each pair reaching `Threshold` with the two Byzantine authorities, which
sign both documents. There is no six-authority configuration asserting that `Agreement`
holds against one fault, because six authorities cannot be searched exhaustively and
`MinimalVoteChoices` must not be used to argue that an invariant holds. The overlap
arithmetic gives that result and `Byzantine4` exhibits the mechanism at even `N`.

Adding a fifth authority makes this worse, not better. With an odd number of
authorities the majority threshold leaves an overlap of exactly one, and one
Byzantine authority can be that one. In the `Byzantine5` trace the honest
authorities split into two pairs, each pair hears the Byzantine authority, and
it signs both pairs' documents.

### One Byzantine authority can split the honest documents

`Equivocation` runs at `N = 4`, where `Agreement` holds. Every vote and
certificate is delivered. The Byzantine authority sends a vote containing
descriptor `n1` to one honest authority and a vote without it to the others.
Two honest authorities have `n1` in their own view. The favoured authority
counts three votes for `n1` and includes it. The others count two and do not.

The honest authorities therefore compute different documents with nothing
lost in transit. This follows `tallyVotes()`, which counts every stored vote
and never consults the equivocation findings of `verifyCommits()`. Safety is
unaffected, since `Byzantine4` passes. The cost is liveness: the split
authority cannot finalise, and if the Byzantine authority also withholds its
signature the remaining two honest authorities cannot reach three.

### The same equivocation stops a document being signed at all

`Shape` gives the nodes the roles `IsDocumentWellFormed` checks: three mix
layers, the gateways, the service nodes. An authority whose tally leaves any of
them short holds a document that function refuses, and `getMyConsensus` returns
an error before it signs, so it computes nothing rather than something that
differs from its peers'.

The trace is the `Equivocation` attack against that shape, with every vote and
certificate delivered and the priors in agreement. One Byzantine authority
varies a single descriptor between peers, that descriptor falls below threshold
in one honest authority's tally, its layer empties, and the authority signs
nothing. So the cost of descriptor equivocation is not only that honest
authorities disagree: an authority can be left with no document to sign, and at
three authorities that is the whole round.

### What the per-layer minimum would cost, if anything applied it

The authority config has a `MinNodesPerLayer` knob, default 2. Two functions in
`state.go` would apply it, `hasEnoughDescriptors` and `verifyTopology`, and at
`e17bffb95` neither is called from anywhere in the repository. So per epoch the
only per-layer rule in force is `IsDocumentWellFormed`'s, which is that a layer
is not empty. The knob binds once, in `New()`, against the size of the
whitelist, under a comment that says it assumes every whitelisted node posts a
descriptor.

`ShapeMinTwo` is the rule as written rather than as enforced: two mix layers of
two nodes with `MinPerLayer = 2`. It matters because that is the shape of the
deployed network's first two layers, which hold two mixes each. At
`MinPerLayer = 1` such a layer survives losing one of its two nodes; at 2 it
does not, so the same equivocation that costs the round nothing today would
cost it the epoch if the knob were ever wired up. Both readings produce a
counterexample, and the difference between them is how much slack a layer has.

### The shared-random chain

`EpochsByzantine` shows the consequence of an `Agreement` violation at the
next boundary. Two different documents each hold `Threshold` signatures, the
two honest authorities chain onto different ones, and the chain forks.

`WitnessChainRestart` shows a weaker effect that needs no Byzantine authority.
An honest authority that fails to finalise, and whose fetch does not land,
enters the next epoch on the zero value while its peers chain onto the
previous document. Its document then differs from theirs, so it cannot
contribute a signature that epoch. `ChainConsistency` still holds, because
that authority has restarted the chain and not joined a competing one.

## Tuning the state space

Delivery is an arbitrary subset per authority per round, so the state space
grows quickly with `Auths`. Four authorities with one node is about six
million states. Adding a second node to `Byzantine4` has not been attempted.

Five authorities cannot be searched exhaustively as the model stands. The
vote round alone has over a million outcomes, which exceeds TLC's default
limit on the size of an enumerated set. `-maxSetSize 3000000` lifts the limit,
and the run then takes minutes per step.
