# TLA+ models of the mix server

Two models of a mix node, from the `server` package as it is on `main` at commit
`e17bffb95`.

| Model | Covers |
|---|---|
| [`MixNode.tla`](MixNode.tla) | the path of a packet: waiting, routing, mixing, drops |
| [`MixKeys.tla`](MixKeys.tla) | key rotation, forward secrecy and replay protection |

They are separate because the two mechanisms barely interact: a packet either
unwraps or it does not, and that one bit is all the pipeline needs to know about
keys.

## The packet pipeline: `MixNode.tla`

```
incoming connection -> crypto worker -> scheduler -> outgoing connection
```

| Step | What happens | Code |
|---|---|---|
| `Arrive` | A packet arrives, stamped with its arrival time and origin. | `onSendPacket` |
| `Unwrap` | A crypto worker drops it, or decides where it goes. | `worker`, `routePacket` in `cryptoworker` |
| `Enqueue` | The scheduler checks the delay and the next hop, and queues it. | `worker` in `scheduler` |
| `Dispatch` | The scheduler takes a due packet and sends or drops it. | `worker` in `scheduler`, `DispatchPacket` |
| `Flap` | The connection to the next hop comes or goes. | |
| `Tick` | Time passes. | |

The role is chosen at the start and all three are explored: mix, gateway and
service node. Following the code: the wait for a crypto worker counts towards the
delay, since `routePacket` takes it off the delay the sender asked for and never
hands over less than a millisecond; two flags are set on arrival, so a packet from
a client must be forwarded and a packet from a mix to a service node must end
there; the next hop is checked twice, at `IsValidForwardDest` and again at
`DispatchPacket`, and the connection may go away in between; drop reasons are the
labels the code reports to its metrics.

| Invariant | Statement |
|---|---|
| `MinimumMixing` | A packet that is sent spent at least the requested delay in the node, and at least one tick. |
| `ClientPacketsAreMixed` | A packet from a client never reaches a local backend or the decoy handler. |
| `ServiceNodeTerminates` | A service node sends on nothing that a mix gave it. |
| `MixHasNoBackend` | Nothing reaches a backend on a mix. |
| `PlaceMatchesCommand` | Only forward packets are sent on; only decoy replies reach the decoy handler. |
| `TypeOK` | Type invariant. |

## Keys and replays: `MixKeys.tla`

A mix key belongs to one epoch. Once per epoch `publishDescriptorIfNeeded`
prepares the next epoch's descriptor, and that step also manages the keys. Apart
from start-up it is the only place that does.

| Step | What happens | Code |
|---|---|---|
| `Publish` | Keys for the next three epochs are generated; keys older than the previous epoch are pruned. | `Generate`, `Prune` |
| `Reshadow` | A crypto worker copies the key set. | `UpdateMixKeys`, `Shadow` |
| `Accept` | A crypto worker accepts a packet and records its tag. | `doUnwrap`, `IsReplay` |
| `NextEpoch` | The epoch ends. | |
| `Shutdown` | The node stops cleanly and writes every key to a file. | `Halt`, `Persist` |
| `Boot` | The node starts, loads the key files it can use, removes the rest. | `purgeStaleKeyFiles`, `Generate`, `Load` |

Following the code: a key is destroyed when its last holder lets go, the node and
each worker being holders, pruning removing it from the node and a worker letting
go when it copies the key set again; a worker tries the keys of the previous,
current and next epoch, and refuses every packet if it lacks the current one;
there is one replay filter per key, shared by all workers, and testing and
setting a tag is atomic; a key file holds the private key and nothing else, so a
loaded key starts with an empty filter.

`MaxSkips` sets how many epochs may pass without the publish step, and `Restarts`
lets the node shut down and boot with its keys saved, which is the option
`PersistMixKeysOnShutdown`, off by default. An epoch passes without the publish
step when its upload window has closed, when the step fails before it reaches the
keys, or when the node has stopped advertising itself, the last happening under
`WaitForConsensusExitOnShutdown`, where a node asked to stop keeps serving traffic
until it has left the consensus.

| Invariant | Statement |
|---|---|
| `ReplayFreedom` | No packet is accepted twice. |
| `KeysDestroyedOnTime` | The key of epoch `k` is destroyed before epoch `k + 3` begins. |
| `KeysAvailable` | While the node runs, every worker holds the keys of the current and next epoch. |
| `TypeOK` | Type invariant. |

`KeysDestroyedOnTime` is the forward secrecy property: a key is last usable in
epoch `k + 1` and the publish step of epoch `k + 2` prunes it, where a key counts
as existing while the node, a worker or a file holds it.

Without restarts `ReplayFreedom` holds by construction, since a packet is
accepted only if its tag is new, accepting it records the tag, and the filter
never shrinks. There it documents the mechanism rather than testing the code.
With restarts it can fail, and does.

## Results

| Model | Config | Expected | Distinct states |
|---|---|---|---|
| `MixNode` | `Pipeline` | all six hold | 6,591,120 |
| `MixNode` | `WitnessSent` | `NeverSent` violated | |
| `MixNode` | `WitnessDelivered` | `NeverDelivered` violated | |
| `MixNode` | `WitnessShortened` | `NeverShortened` violated | |
| `MixKeys` | `Healthy` | all four hold | 44,184 |
| `MixKeys` | `OneSkip` | three hold | 121,328 |
| `MixKeys` | `OneSkipSecrecy` | `KeysDestroyedOnTime` violated | |
| `MixKeys` | `TwoSkips` | `KeysAvailable` violated | |
| `MixKeys` | `Restart` | two hold | 113 |
| `MixKeys` | `RestartReplay` | `ReplayFreedom` violated | |
| `MixKeys` | `RestartSecrecy` | `KeysDestroyedOnTime` violated | |
| `MixKeys` | `WitnessAccepts` | `NeverAccepts` violated | |
| `MixKeys` | `WitnessDestroys` | `NeverDestroys` violated | |

Each file is `<Model>_<Config>.cfg` and says in its own comment what its result
shows. Counts are from TLC 2.19, the release `make tla` pins. A failing
configuration has no stable count, because TLC stops at the first counterexample
its workers reach and which one that is varies between runs of an unchanged tree.
Invariants named `Never` are expected to fail and exist to produce a witness.

`MixNode` runs with 2 packets, 5 ticks, an unwrap delay of 2, scheduler slack of
1 and a longest delay of 3. `MixKeys` runs with 2 workers, 6 epochs, 2 tags or
none, and `MaxSkips` 0, 1 or 2. `Restart` and `RestartSecrecy` run with no tags
and so no packets, because whether a key exists does not depend on packets and
with restarts they multiply the states beyond what can be searched.

## What the models show

**The pipeline does what it is meant to.** Every property holds for all three
roles, with the connection to the next hop coming and going at will.

**A packet may spend less than its delay in the scheduler, but never less in the
node.** `WitnessShortened` shows one that waited for a crypto worker and was then
held for less than the delay its sender asked for; `MinimumMixing` shows the two
together are never less than that delay.

**Forward secrecy and the supply of keys both depended on the publish step.**
At `e17bffb95`, `Prune` and, apart from start-up, `Generate` had one call site
each, inside `publishDescriptorIfNeeded`, so an epoch that passed without that
step pruned and generated nothing. The PKI worker now rotates every pass, so this
is what the model found rather than what the code does; the configurations still
exhibit it, because they model the code as it was. `OneSkipSecrecy` shows the key of epoch 1 still existing in
epoch 4 after epoch 3 was skipped, when it should have been pruned in epoch 3.
One skipped epoch costs no availability, as `OneSkip` shows, but after two in a
row the node has no key for the next epoch (`TwoSkips`), and after three it would
have none for the current one and would refuse every packet. Both findings were
read from the code and checked in the model, not reproduced by running the server.

**A restart with saved keys lets a packet through twice.** `RestartReplay` shows
a worker accepting a packet under the key of epoch 1, a clean shutdown writing
that key to a file, a boot loading it with a new and empty filter, and a worker
accepting the same packet again. `Persist` writes the private key and `Load`
builds the key around a fresh filter, so anyone who recorded a packet before the
restart can send it again afterwards for as long as the key is tried, and the node
will treat it as new. Saving the filter with the key restores the property in the
model. This one was replayed against the server code, in
[`mixkey_replay_repro_test.go.txt`](mixkey_replay_repro_test.go.txt) with
instructions at the top; it passes while the problem is present. The option is off
by default, and the code says why: a node that starts with fresh keys has forward
secrecy across the restart.

**Saved keys outlive their epoch while the node is down.** `RestartSecrecy` shows
a node that shuts down in epoch 1 and is still down in epoch 4 with that key on
disk, the files being removed at the next boot and not before. By default they are
kept in memory-backed storage, so they do not survive the machine being switched
off.

## What is not checked, and what is not modelled

Two rules are in the models because the code has them, though no invariant
depends on either, which a mutation test confirmed: the three keys a worker tries,
where widening it to every key the worker holds breaks nothing, and dropping a
packet that asked for no delay and still had to wait, where keeping it breaks
nothing because it would be held for one tick anyway.

Not modelled: cryptography, a packet unwrapping under the key of its epoch and no
other; the Bloom filter, the modelled one being exact where the real one may also
reject a fresh tag; a restart without saved keys, and a crash, after which no
earlier packet unwraps; a full replay filter, after which the code treats every
further packet for that key as a replay; a clock that goes backwards; slow
workers, every worker here copying the key set within the epoch it was told to;
decoy packets the node creates, which the code hands straight to the outgoing
connection; the rate limit on clients, the scheduler queue's size limit, the burst
limit and a delay limit from the PKI document; the scheduler's own check of the
delay, which cannot fail without such a limit because the crypto worker has
applied the same bound; the backends; and liveness, only invariants being checked.

Each invariant expected to hold was mutation-tested, by introducing a deliberate
error into a copy of the specification and confirming TLC reported it violated.
The constants matter to that: with a longest delay of 2 ticks and a longest wait
of 1, taking the wait off the delay twice went unnoticed, which is why the
configurations use 3 and 2.

## Running

`make tla` from the repository root fetches the pinned tla2tools through
`make tla-tools`, which checks its digest, and runs every configuration of every model through
[`.ci/tla.sh`](../../.ci/tla.sh), comparing each verdict with the expected one
and exiting non-zero if any differs.

For one configuration and its trace, with the jar here or named by `TLA2TOOLS`:

```sh
java -jar tla2tools.jar -config MixKeys_OneSkipSecrecy.cfg MixKeys.tla
```
