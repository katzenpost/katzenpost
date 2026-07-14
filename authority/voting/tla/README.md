# TLA+ model of the voting directory authority

A formal model of the Katzenpost voting directory-authority consensus
protocol implemented in
[`authority/voting/server/state.go`](../server/state.go).

## What is modelled

The real authority runs a timed finite-state machine over one epoch:

```
AcceptDescriptor -> AcceptVote -> AcceptReveal -> AcceptCert -> AcceptSignature
   (1/8)            (2/8)          (3/8)           (4/8)         (5/8)
```

`VotingAuthority.tla` abstracts the timed FSM into three message-exchange
rounds that capture the consensus-relevant behaviour:

| Round    | Models                                                                 |
|----------|------------------------------------------------------------------------|
| `vote`   | Each authority broadcasts its vote (descriptor view + SR commitment).  |
| `cert`   | Authorities exchange certificates, detect equivocation, tally a doc.   |
| `sig`    | Authorities exchange signatures; a doc is finalised at `Threshold`.    |

Key faithful elements:

- **Threshold** = `floor(N/2) + 1` (matches `st.threshold` in `state.go`).
- **Equivocation detection**: an authority seen reporting different
  vote/commit content to different peers is excluded from the tally and the
  shared-random set (mirrors `verifyCommits()`).
- **Threshold signatures**: an honest authority signs only its own computed
  document; a document is finalised only with `Threshold` signatures over it
  (mirrors `cert.VerifyThreshold`).
- **Lossy/asynchronous delivery**: in every round each authority receives
  messages from an arbitrary subset of authorities.
- **Epoch boundary / SRV chaining**: the model runs `MaxEpoch` consecutive
  epochs. Each epoch's consensus produces a shared-random value (SRV) that is
  mixed into the next epoch's documents (`srv = BLAKE2b(... || prior_srv)` in
  `state.go`). At the boundary a unique threshold document propagates its SRV
  to every honest authority (lagging authorities catch up via the bootstrap
  fetch); a failed epoch stalls the chain; a Byzantine fork splits it.

Deliberate abstractions (see the header comment in the `.tla` for the full
list): symbolic cryptography, the BLAKE2b SRV reduced to the participant set,
and the reveal round folded into the vote round.

## Properties checked

- `Agreement` (safety) — no two honest authorities finalise different
  documents.
- `Validity` (safety) — a finalised document was computed by some honest
  authority.
- `Integrity` (safety) — a finalised document carries `Threshold` signatures.
- `ChainConsistency` (safety, epoch boundary) — all honest authorities agree
  on the prior-epoch SRV they chain the current epoch onto.
- `ChainGrounded` (safety, epoch boundary) — a finalised document chains onto
  an SRV from a strictly earlier epoch (or genesis).
- `TypeOK` — type invariant.

## Configurations

| Config                                | Auths | Byz | Nodes | Epochs | Expected result                         |
|---------------------------------------|-------|-----|-------|--------|-----------------------------------------|
| `VotingAuthority_Honest.cfg`          | 3     | 0   | 1     | 1      | all invariants hold                     |
| `VotingAuthority_Byzantine.cfg`       | 3     | 1   | 1     | 1      | `Agreement` counterexample              |
| `VotingAuthority_Epochs.cfg`          | 3     | 0   | 0     | 2      | all invariants hold (incl. chain props) |
| `VotingAuthority_EpochsByzantine.cfg` | 3     | 1   | 0     | 2      | `ChainConsistency` counterexample       |

## Running

Requires `tla2tools.jar` (TLC). Download from
<https://github.com/tlaplus/tlaplus/releases>, or use the TLA+ Toolbox / the
VS Code "TLA+" extension.

From this directory:

```sh
# Honest / crash-fault case: all invariants hold.
java -jar tla2tools.jar -config VotingAuthority_Honest.cfg VotingAuthority.tla

# One Byzantine authority among three: TLC finds an Agreement counterexample.
java -jar tla2tools.jar -config VotingAuthority_Byzantine.cfg VotingAuthority.tla

# Two epochs, honest: ChainConsistency and all other invariants hold.
java -jar tla2tools.jar -config VotingAuthority_Epochs.cfg VotingAuthority.tla

# Two epochs, one Byzantine: TLC finds a ChainConsistency (SRV fork) counterexample.
java -jar tla2tools.jar -config VotingAuthority_EpochsByzantine.cfg VotingAuthority.tla
```

### Interpreting the Byzantine result

With `N = 3` the threshold is `2`. TLC reports an `Agreement` violation with a
short trace: lossy delivery leaves the two honest authorities with different
views, so they compute different documents; the single Byzantine authority
then signs *both* documents, supplying the deciding second signature for each.
Both honest authorities finalise, but on different documents.

Note the honest configuration passes *all* invariants even under arbitrary
message loss: omission/crash faults alone never break agreement. The
violation requires a Byzantine authority that signs more than one document.
This is the expected, well-known result: a simple majority quorum (`2f+1`)
tolerates crash/omission faults but not Byzantine faults; Byzantine agreement
requires `3f+1`. The model makes that boundary explicit and reproducible.

### Interpreting the epoch-boundary result

The multi-epoch Byzantine run shows the consequence of a single-epoch
Agreement violation at the *next* epoch boundary: two honest authorities adopt
different SRVs (e.g. one keeps the genesis value while the other adopts
`[epoch 1, {a2}]`), so the shared-random chain forks and stays forked. This
demonstrates that consensus safety in any one epoch is what keeps the SRV
chain — and therefore the deterministic mix topology derived from it —
consistent across epochs.


### Producing a successful-consensus trace

To see a run where every honest authority finalises the *same* document, ask
TLC to check the (intentionally false) invariant `ConsensusUnreachable`; the
reported "counterexample" is a successful consensus run:

```sh
java -jar tla2tools.jar -config VotingAuthority_Honest.cfg \
     -invariant ConsensusUnreachable VotingAuthority.tla
```

## Tuning the state space

The default instance (3 authorities, 1 node) is small and fast. Increasing
`Auths` or `Nodes` in the `.cfg` files grows the state space quickly because
delivery is modelled as an arbitrary subset per authority per round. Start
small.
