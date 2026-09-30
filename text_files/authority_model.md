# The directory authority and its TLA+ model

This document has three parts. The first explains how the voting directory
authority works. The second describes the TLA+ model of it. The rest records
a review of that model: what was changed, what the model checker found, and
what the results do and do not establish.

The implementation is in
[`authority/voting/server/state.go`](../authority/voting/server/state.go).
The model is in [`authority/voting/tla/`](../authority/voting/tla/).

The document describes the code as it is on `main` at commit `91debb674`.

## How the directory authority works

### Purpose

A Katzenpost network needs every participant to agree on who the nodes are.
A small, fixed set of directory authorities provides that. Once per epoch they
jointly publish one signed document, the consensus. It lists the mix nodes,
gateway nodes, service nodes and storage replicas, assigns the mixes to
layers, fixes the network parameters, and carries a shared random value.

Clients and nodes accept a document only if it carries valid signatures from
a threshold of the authorities. The threshold is a strict majority:
`floor(N/2) + 1` of `N` authorities. No single authority can publish a
document alone.

### The epoch schedule

An epoch lasts 20 minutes by default. During each epoch the authorities
produce the document for the next one. Every authority runs the same state
machine, driven by its own clock, and moves to the next phase at a fixed
fraction of the epoch.

| Deadline | At the deadline the authority                 | State it enters    |
|----------|-----------------------------------------------|--------------------|
| 1/8      | builds its vote and sends it to its peers     | `accept_vote`      |
| 2/8      | sends its reveal                              | `accept_reveal`    |
| 3/8      | builds its certificate and sends it           | `accept_cert`      |
| 4/8      | computes its document and sends its signature | `accept_signature` |
| 5/8      | counts signatures and publishes or fails      | `accept_desc` or `bootstrap` |

Nodes are expected to upload their descriptors before the first deadline.

The state decides what the authority sends and when. It does not decide what
the authority accepts. The handlers for incoming votes, certificates and
signatures check the epoch a message is for, and not the state the authority
is in.

### Descriptors

Each node uploads a signed descriptor for the coming epoch: its keys, its
addresses and its role. An authority keeps a descriptor only from a node
listed in its own configuration, and checks that again when it tallies. A
node cannot replace a descriptor it has already uploaded for an epoch. A
second, different upload is rejected.

Authorities can end the upload phase holding different sets of descriptors,
because uploads can be lost or arrive late. The rest of the protocol exists
to turn those different views into one document.

### Votes

A vote is a signed document containing every descriptor the authority holds,
its parameters, and its commitment to a random value. An authority stores the
first vote it receives from each peer and rejects any later one from the same
peer.

A vote is accepted only on the connection of the authority that signed it.
The same holds for a reveal, a certificate and a signature. An authority
cannot pass on what another authority sent.

### Commit and reveal

The shared random value must not be open to manipulation by an authority that
waits to see what the others contributed. So each authority first commits to
a random value inside its vote, and discloses the value only after the vote
deadline. A reveal is accepted only from a peer whose commitment is already
held, and only if it opens that commitment.

### Certificates

A certificate is the authority's tally of the votes it holds, together with
the commitments and reveals it has seen. A commitment is included only if its
reveal arrived too. An authority whose reveal was lost is left out, and the
round goes on without its contribution to the shared random value. Its vote
still counts in the tally.

An authority builds a certificate only if it holds a threshold of votes. It
accepts one only from a peer whose vote it already holds.

Certificates let each authority see what its peers were told. If two
certificates show different commitments from the same authority, that
authority sent different values to different peers.

### Computing the document

At the certificate deadline each authority computes its own view of the
consensus, in `getMyConsensus()`. It refuses unless it holds a threshold of
certificates.

1. **Check the commitments.** `verifyCommits()` compares the commitments and
   reveals across all certificates held. An authority that presented two
   different commitments is excluded from the shared random value. A
   threshold of consistent commitments must remain.
2. **Compute the shared random value.** `computeSharedRandom()` hashes the
   epoch number, the accepted reveals, and the previous epoch's shared random
   value. If the authority has no document for the previous epoch it hashes
   32 zero bytes in its place.
3. **Tally the descriptors.** `tallyVotes()` includes a descriptor if it
   appears in a threshold of the votes the authority received directly.
   Parameters are tallied the same way. This step does not use the result of
   step 1, so a vote counts even if its sender was caught equivocating.
4. **Build the topology.** Mixes are assigned to layers using the shared
   random value as the seed, starting from the previous topology where there
   is one. Authorities with the same inputs produce the same layers.

The authority signs the result and sends the signature to its peers. It signs
nothing else.

### Reaching consensus

At the last deadline each authority adds the signatures it received to its
own document, in `getThresholdConsensus()`. A signature counts only if it is
valid over that exact document. Two authorities that computed different
documents therefore cannot help each other.

With a threshold of signatures the document becomes the consensus. The
authority stores it, writes it to disk, and serves it to clients and nodes.

Without a threshold the epoch has failed for that authority. It enters the
bootstrap state and asks its peers for the documents it lacks. A fetched
document is accepted only with a threshold of signatures. The authority takes
part in the next vote whether or not the fetch has finished.

### What each mechanism protects

| Mechanism                       | Protects against                                            |
|---------------------------------|-------------------------------------------------------------|
| Threshold signatures            | a minority of authorities publishing a document             |
| Signing only one's own document | an honest authority endorsing something it did not compute  |
| Descriptor tally at threshold   | a minority of authorities adding a node                     |
| Commit then reveal              | an authority choosing its randomness after seeing the rest  |
| Commitments in certificates     | an authority sending different commitments to different peers |

The table states what each mechanism is for. How far each one holds against
a misbehaving authority is what the model examines. The findings are under
[What the model shows about the protocol](#what-the-model-shows-about-the-protocol).

## The model

### What a model checker does here

The model is a TLA+ specification, checked with TLC. It describes the protocol
as a set of states and the steps that lead from one state to the next. TLC
visits every state that can be reached, for a small number of authorities, and
checks that a stated property holds in each one. If a property fails, TLC
prints the sequence of steps that led to the failure.

The value of this is coverage. Every pattern of message loss and every choice
open to a misbehaving authority is tried, within the limits of the model. The
cost is that only small instances are feasible, and that the model is a
simplification of the code.

### Parameters

| Constant    | Meaning                                             |
|-------------|-----------------------------------------------------|
| `Auths`     | the authorities                                     |
| `Byzantine` | the authorities that may behave arbitrarily         |
| `Nodes`     | the descriptors that may be voted on                |
| `MaxEpoch`  | the number of consecutive epochs to run             |

The model assumes fewer Byzantine authorities than the threshold.

### State

| Variable   | Holds                                                        |
|------------|--------------------------------------------------------------|
| `epoch`    | the current epoch                                            |
| `phase`    | `vote`, `cert`, `sig` or `done`                              |
| `voteMsg`  | the vote each authority sent to each other authority         |
| `recvVote` | whose votes each authority received                          |
| `recvCert` | whose certificates each honest authority accepted            |
| `myDoc`    | the document each honest authority computed, if any          |
| `sigSet`   | the documents each authority signed                          |
| `finalDoc` | the document each honest authority finalised, if any         |
| `priorSRV` | the shared random value each honest authority chains onto    |

A document is a record of four things: the epoch, the set of agreed
descriptors, the set of authorities that contributed to the shared random
value, and the prior shared random value.

### Steps

Each epoch is four steps. Every authority takes each step at once.

| Step           | What happens                                                            | Code it stands for                        |
|----------------|-------------------------------------------------------------------------|-------------------------------------------|
| `DeliverVote`  | Each authority receives the votes of some set of authorities.           | `getVote`, `onVoteUpload`                 |
| `DeliverCert`  | Each authority accepts some certificates and computes its document.     | `getCertificate`, `onCertUpload`, `getMyConsensus` |
| `DeliverSig`   | Authorities sign. Each one whose document has enough signatures may finalise. | `onSigUpload`, `getThresholdConsensus` |
| `EpochAdvance` | Each authority settles its prior shared random value. A new epoch begins. | `stateBootstrap`, `backgroundFetchConsensus` |

The document an authority computes follows the four steps of
`getMyConsensus()` described above, without the topology.

### How loss is modelled

In every round, each authority receives messages from an arbitrary subset of
the authorities. TLC tries every combination. This covers a lost message, a
crashed authority, and an authority that chooses whom to send to.

The signature round does not record who received what. An authority finalises
exactly when it received a threshold of signatures over its document. So an
authority whose document holds that many signatures may or may not finalise,
and one whose document holds fewer cannot. The model states that directly.

### How Byzantine behaviour is modelled

A Byzantine authority can do four things.

- **Send different votes to different peers.**
- **Issue a certificate that claims any set of received votes.**
- **Sign any number of documents**, where an honest authority signs one.
- **Serve any document that holds a threshold of signatures** to a peer that
  is catching up.

It cannot forge a signature or a commitment.

### How the shared random value is modelled

The real value is a hash. The model replaces it with the list of inputs that
went into it: one entry per epoch, naming the epoch and the contributing
authorities, oldest first. Two values are equal exactly when their histories
are equal. The empty list stands for the 32 zero bytes.

At the end of an epoch, an authority that finalised extends its list with the
new entry. An authority that did not finalise either receives a
threshold-signed document from a peer, or starts again from the empty list.

### What the model checks

The properties are listed under [Changes to the
properties](#changes-to-the-properties). In short, they are these four
claims. Whether each one holds depends on how many authorities there are and
how many are Byzantine, which is what the configurations vary.

- **Agreement.** Honest authorities never finalise different documents, and
  no two documents both gather a threshold of signatures.
- **Descriptor validity.** A descriptor in an honest document was voted for by
  an honest authority.
- **Chain integrity.** The shared random chain does not fork and does not skip
  an epoch.
- **Convergence.** With nothing lost and a common prior shared random value,
  all honest authorities compute the same document.

The model is about 160 lines of TLA+ and runs in ten configurations. What it
leaves out is listed under [Limits](#limits).

## Review and changes

This part summarises a review and revision of the model.

The changes are in the working tree on branch `tla` and are not committed.
The working tree already held uncommitted edits to the model when the review
began. This summary covers what was changed on top of those.

### Starting point

The model as found was self-consistent. TLC 2.19 reproduced the four results
its README promised:

| Config            | Result                        |
|-------------------|-------------------------------|
| `Honest`          | no violation                  |
| `Epochs`          | no violation                  |
| `Byzantine`       | `Agreement` violated          |
| `EpochsByzantine` | `ChainConsistency` violated   |

The review compared the specification with `state.go` function by function,
and found the problems below.

### Problems found

1. **A documented command did not work.** The README told the reader to pass
   `-invariant ConsensusUnreachable` to TLC. TLC has no such option.
2. **The model was stronger than the code in ways that could be fixed.** The
   README listed these as known divergences. Each one meant a property proved
   of the model was not established of the implementation.
   - Equivocators were excluded from the descriptor tally. `tallyVotes()`
     counts every stored vote.
   - Votes spread through certificates. `onCertUpload()` never adds to
     `s.votes`.
   - A certificate was accepted from any authority. `onCertUpload()` rejects
     one from a peer whose vote has not arrived.
   - An authority always computed and signed a document. `tallyVotes()` and
     `getMyConsensus()` refuse without `Threshold` votes, certificates and
     commitments.
3. **The epoch boundary was an assumption.** Every honest authority was handed
   the winning shared-random value. In the code an authority that fails to
   finalise depends on `backgroundFetchConsensus()`, which may not land in
   time.
4. **A failed epoch carried the old shared-random value forward.**
   `computeSharedRandom()` writes 32 zero bytes when the previous document is
   absent.
5. **A shared-random value ignored its history.** It was modelled as an epoch
   and a participant set. Two chains that diverged earlier could compare
   equal.
6. **`ChainGrounded` was too weak with two epochs.** A specification with a
   deliberate error in the epoch boundary passed it.
7. **Signature delivery sets were stored in the state** although nothing read
   them after the step that chose them. This inflated the state space and put
   a four-authority run out of reach.

### Changes to the specification

File: [`VotingAuthority.tla`](../authority/voting/tla/VotingAuthority.tla)

| Area                 | Before                                        | After                                                          |
|----------------------|-----------------------------------------------|----------------------------------------------------------------|
| Descriptor tally     | over all known voters, equivocators excluded  | over directly received votes, no exclusion                     |
| Certificates         | accepted from anyone                          | accepted only from a peer whose vote arrived                   |
| Issuing a certificate| always                                        | honest authority needs `Threshold` votes                       |
| Computing a document | always                                        | needs `Threshold` votes, certificates and commitments          |
| Shared-random value  | epoch and participant set                     | the chain of links it derives from                             |
| Epoch boundary       | everyone adopts the unique consensus          | finalisers keep their own, others fetch or restart from zero   |
| Failed epoch         | old value carried forward                     | chain restarts from the zero value                             |
| Signature round      | delivery sets recorded in state               | each eligible authority may or may not finalise                |
| Byzantine assumption | implicit                                      | `ASSUME Cardinality(Byzantine) < Threshold`                    |

Two changes are for the model checker only and do not alter behaviour. The
state counts of the passing configurations were identical before and after
each.

- Delivery choices are built by a recursive product operator, so TLC
  enumerates only the valid ones.
- A `Symmetry` definition lets a configuration treat honest authorities,
  Byzantine authorities and nodes as interchangeable.

### Simplification pass

After the changes above, the specification was reviewed again for accuracy
and for anything that could be removed. It went from 198 lines of TLA+ to 164,
not counting comments and blank lines.

| Removed or simplified                                     | Why it is safe                                                      |
|-----------------------------------------------------------|---------------------------------------------------------------------|
| Variable `descView`                                       | An honest authority's view is the vote it sends, `voteMsg[h][h]`.   |
| Field `valid` of a document                               | `NoDoc` has epoch 0, which no document has.                         |
| Byzantine entries of `priorSRV`, `recvCert`, `myDoc`, `finalDoc` | They were constants. These variables now range over honest authorities. |
| The `Threshold` votes condition on computing a document   | Implied: every certificate held is from a peer whose vote is held.  |
| Delivery parameters on `Participants`, `DescTally`, `DocOf` | They were always the same state variables.                        |
| Helper definitions used once                              | Folded into the definition that used them.                          |

The rewrite does not change behaviour. For all four configurations that are
searched exhaustively, the number of distinct states and the number of
transitions are identical before and after. The mutation tests were repeated
on the new text and every mutation was still caught.

The review also corrected one claim carried over from the original header. It
said that using one value for a vote's descriptors and its commitment models
equivocation on either uniformly. It does not. A Byzantine authority could
vary its descriptors under a single commitment and stay a shared-random
participant everywhere, and the model does not explore that. The header and
the README now say so.

### Update after merging main

The model was first written against the branch point, commit `f4c37a3d`.
Main then moved by 654 commits. The authority code changed a good deal, and
every mechanism the model describes is still as the model has it.

| Change on main                                                   | Effect on the model                     |
|------------------------------------------------------------------|-----------------------------------------|
| A lost reveal leaves one authority out of the certificate. Before, it stopped the certificate altogether. | none. The model does not explore a lost reveal. |
| A reveal must open the commitment it answers                     | none. Cryptography is symbolic.         |
| Votes, reveals, certificates and signatures are bound to the connected peer | none. The model already delivered each message from its maker only. |
| A certificate must be for the current epoch and carry reveals    | none                                    |
| The threshold is computed by `votingThresholds()`                | none. The formula is the same.          |
| The parameter tally is keyed differently                         | none. Parameters are not modelled.      |
| The weekly rotation of `PriorSharedRandom` was corrected         | none. It is not modelled.               |
| A missing consensus is fetched over the existing peer connection | none. It is still checked for a threshold of signatures. |

The specification changed in two comments. The documents changed where they
described the old handling of a lost reveal, and where they named code that
has moved.

The findings stand on main. The threshold is the same, so the results for
three, four and five authorities are the same. `tallyVotes()` still counts
the vote of an authority that was caught equivocating, so the split of honest
documents is still possible.

### Changes to the properties

| Invariant                      | Status   | Statement                                                        |
|--------------------------------|----------|------------------------------------------------------------------|
| `Agreement`                    | kept     | No two honest authorities finalise different documents.          |
| `UniqueConsensus`              | new      | At most one document per epoch holds `Threshold` signatures.     |
| `DescriptorValidity`           | new      | Every descriptor in an honest document was in some honest view.  |
| `ConvergenceUnderFullDelivery` | new      | Full delivery and a common prior give equal honest documents.    |
| `ChainConsistency`             | restated | Authorities that chain onto a prior document chain onto the same.|
| `ChainGrounded`                | restated | A chain is consecutive epochs ending at the previous one.        |
| `ChainUnanimity`               | new      | Expected to fail. Witness of a chain restart.                    |
| `ConsensusUnreachable`         | kept     | Expected to fail. Witness of a successful run.                   |

`UniqueConsensus` is stronger than `Agreement`. It covers a threshold-signed
document that no honest authority finalised but that a Byzantine authority
could still serve.

One drafted invariant was discarded. It claimed every shared-random value has
an honest contributor. The authority computing a document is always one of its
own participants, so the claim could never fail. `Validity` and `Integrity`
had been removed earlier for the same reason.

Every invariant that is expected to hold was mutation-tested. An error was
introduced into a copy of the specification and TLC reported the violation.

| Mutation                                           | Caught by                        |
|----------------------------------------------------|----------------------------------|
| `Threshold` lowered to `floor(N/2)`                | `Agreement`, `UniqueConsensus`   |
| Descriptor tally threshold lowered to 1            | `DescriptorValidity`             |
| Failed epoch carries the old prior forward         | `ChainGrounded`, at three epochs |
| Common-prior condition dropped from its premise    | `ConvergenceUnderFullDelivery`   |

## Configurations and results

Six configurations are new. The `Epochs` configuration now runs three epochs
instead of two.

| Config                | Auths | Byz | Nodes | Epochs | Result                                  | Distinct states |
|-----------------------|-------|-----|-------|--------|-----------------------------------------|-----------------|
| `Honest`              | 3     | 0   | 2     | 1      | no violation                            | 152,062         |
| `Epochs`              | 3     | 0   | 1     | 3      | no violation                            | 385,268         |
| `ByzantineValidity`   | 3     | 1   | 1     | 2      | no violation                            | 688,980         |
| `Byzantine4`          | 4     | 1   | 1     | 1      | no violation                            | 6,100,574       |
| `Byzantine`           | 3     | 1   | 1     | 1      | `Agreement` violated                    |                 |
| `Byzantine5`          | 5     | 1   | 0     | 1      | `Agreement` violated                    |                 |
| `EpochsByzantine`     | 3     | 1   | 0     | 2      | `ChainConsistency` violated             |                 |
| `Equivocation`        | 4     | 1   | 1     | 1      | `ConvergenceUnderFullDelivery` violated |                 |
| `WitnessConsensus`    | 3     | 0   | 1     | 1      | `ConsensusUnreachable` violated         |                 |
| `WitnessChainRestart` | 3     | 0   | 0     | 2      | `ChainUnanimity` violated               |                 |

Every result matches its expectation. TLC stops at the first counterexample,
so a failing configuration has no meaningful state count.

The old `Honest` configuration explored 2,130,440 states with one node. The
new one explores 152,062 with two.

## What the model shows about the protocol

**Agreement depends on the parity of the authority count.** Two quorums of
size `Threshold` overlap in at least `2*Threshold - N` authorities. Agreement
survives `f` Byzantine authorities when the overlap exceeds `f`.

| N | Threshold | Overlap | Survives one Byzantine authority |
|---|-----------|---------|----------------------------------|
| 3 | 2         | 1       | no                               |
| 4 | 3         | 2       | yes                              |
| 5 | 3         | 1       | no                               |

Going from four authorities to five makes Byzantine agreement worse. In the
`Byzantine5` trace the honest authorities split into two pairs, each pair
hears the Byzantine authority, and it signs both documents.

**One Byzantine authority can split honest documents where Agreement holds.**
In `Equivocation`, with four authorities and every message delivered, the
Byzantine authority sends different descriptor sets to different peers. One
honest authority counts three votes for a descriptor and the others count two.
Safety is unaffected. The cost is liveness.

**An honest authority can restart the shared-random chain with no Byzantine
authority present.** It fails to finalise, its fetch does not land, and it
enters the next epoch on the zero value. Its document then differs from its
peers' and it cannot contribute a signature that epoch.

**Descriptor injection is not possible** while Byzantine authorities number
fewer than `Threshold`.

## Supporting files

- [`check.sh`](../authority/voting/tla/check.sh) is new. It runs every
  configuration, compares the result with the expected one, and exits
  non-zero on any difference. The suite takes one to two minutes on a 12-core
  machine.
- [`README.md`](../authority/voting/tla/README.md) is rewritten. It lists what
  follows the code, what is not modelled, the properties, the configurations
  and how to read each counterexample.

```sh
cd authority/voting/tla
./check.sh
```

`tla2tools.jar` must be in that directory or named by `TLA2TOOLS`. It is not
committed.

## Limits

- **Scope of the four-authority result.** `Byzantine4` is exhaustive for one
  node descriptor and one epoch. Larger instances were not attempted.
- **The five-authority result is a restricted search.** `Byzantine5`
  substitutes `MinimalVoteChoices` for `VoteChoices`. Every run of the
  restricted specification is a run of the full one, so the counterexample is
  genuine. The same restriction cannot be used to argue that an invariant
  holds.
- **Rounds are synchronous.** Authorities in different phases or epochs at the
  same instant are not explored.
- **The reveal round is folded into the vote round.** In the code a reveal
  can be lost on its own, and that authority is then left out of the
  certificate. The model assumes a reveal arrives wherever its vote does.
- **Byzantine certificates are uniform.** A Byzantine authority sends the same
  certificate to every recipient.
- **Descriptors and commitment are one value.** A Byzantine authority cannot
  equivocate on one without the other.
- **Only safety is checked.** There is no fairness condition and no temporal
  property.
- **Not modelled:** the mix-parameter tally, the refusal to sign a document
  with an empty topology, and the weekly rotation of `PriorSharedRandom`.
