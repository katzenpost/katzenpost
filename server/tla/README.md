# TLA+ models of the mix server

Two formal models of a Katzenpost mix node, taken from the `server` package
as it is on `main` at commit `91debb674`.

| Model                        | Covers                                                  |
|------------------------------|---------------------------------------------------------|
| [`MixNode.tla`](MixNode.tla) | the path of a packet: waiting, routing, mixing, drops   |
| [`MixKeys.tla`](MixKeys.tla) | key rotation, forward secrecy and replay protection     |

They are separate because the two mechanisms barely interact. A packet either
unwraps or it does not, and that one bit is all the pipeline needs to know
about keys.

## The packet pipeline: `MixNode.tla`

```
incoming connection -> crypto worker -> scheduler -> outgoing connection
```

| Step       | What happens                                                         | Code                                   |
|------------|----------------------------------------------------------------------|----------------------------------------|
| `Arrive`   | A packet arrives and is stamped with its arrival time and its origin. | `onSendPacket`                         |
| `Unwrap`   | A crypto worker drops it, or decides where it goes.                  | `worker`, `routePacket` in `cryptoworker` |
| `Enqueue`  | The scheduler checks the delay and the next hop, and queues it.      | `worker` in `scheduler`                |
| `Dispatch` | The scheduler takes a packet that is due and sends or drops it.      | `worker` in `scheduler`, `DispatchPacket` |
| `Flap`     | The connection to the next hop comes or goes.                        |                                        |
| `Tick`     | Time passes.                                                         |                                        |

The role of the node is chosen at the start and explored for all three
values: mix, gateway and service node.

Elements that follow the code:

- **The wait for a crypto worker counts towards the delay.** `routePacket`
  takes the wait off the delay the sender asked for, and never hands over
  less than one millisecond.
- **Two flags set on arrival.** A packet from a client must be forwarded. A
  packet from a mix to a service node must end there.
- **The next hop is checked twice.** Once when the packet is queued
  (`IsValidForwardDest`) and once when it is sent (`DispatchPacket`). The
  connection may go away in between.
- **Drop reasons** are the labels the code reports to its metrics.

### Properties

| Invariant               | Statement                                                                 |
|-------------------------|---------------------------------------------------------------------------|
| `MinimumMixing`         | A packet that is sent spent at least the requested delay in the node, and at least one tick. |
| `ClientPacketsAreMixed` | A packet from a client never reaches a local backend or the decoy handler. |
| `ServiceNodeTerminates` | A service node sends on nothing that a mix gave it.                       |
| `MixHasNoBackend`       | Nothing reaches a backend on a mix.                                       |
| `PlaceMatchesCommand`   | Only forward packets are sent on. Only decoy replies reach the decoy handler. |
| `TypeOK`                | Type invariant.                                                           |

## Keys and replays: `MixKeys.tla`

A mix key belongs to one epoch. Once per epoch the PKI worker prepares the
descriptor for the next epoch, in `publishDescriptorIfNeeded`. That step also
manages the keys. Apart from start-up, it is the only place that does.

| Step        | What happens                                                         | Code                         |
|-------------|----------------------------------------------------------------------|------------------------------|
| `Publish`   | Keys for the next three epochs are generated. Keys older than the previous epoch are pruned. | `Generate`, `Prune` |
| `Reshadow`  | A crypto worker copies the key set.                                  | `UpdateMixKeys`, `Shadow`    |
| `Accept`    | A crypto worker accepts a packet and records its tag.                | `doUnwrap`, `IsReplay`       |
| `NextEpoch` | The epoch ends.                                                      |                              |
| `Shutdown`  | The node stops cleanly and writes every key to a file.               | `Halt`, `Persist`            |
| `Boot`      | The node starts, loads the key files it can use, and removes the rest. | `purgeStaleKeyFiles`, `Generate`, `Load` |

Elements that follow the code:

- **A key is destroyed when its last holder lets go.** The node and each
  crypto worker hold it. Pruning removes it from the node. A worker lets go
  when it copies the key set again.
- **A worker tries three keys**: those of the previous, current and next
  epoch. It refuses every packet if it lacks the key of the current epoch.
- **One replay filter per key**, shared by all workers. Testing and setting a
  tag is one atomic step.
- **A key file holds the private key and nothing else.** A key that is loaded
  starts with an empty replay filter.

Two constants widen what the node may do.

| Constant   | Meaning                                              | In the code                                   |
|------------|------------------------------------------------------|-----------------------------------------------|
| `MaxSkips` | how many epochs may pass without the publish step    | see below                                     |
| `Restarts` | the node may shut down and boot with its keys saved  | the option `PersistMixKeysOnShutdown`, off by default |

An epoch passes without the publish step in three cases: its upload window
has closed, the step fails before it reaches the keys, or the node has
stopped advertising itself. The last happens with
`WaitForConsensusExitOnShutdown`, where a node that is asked to stop keeps
serving traffic until it has left the consensus.

### Properties

| Invariant             | Statement                                                              |
|-----------------------|------------------------------------------------------------------------|
| `ReplayFreedom`       | No packet is accepted twice.                                           |
| `KeysDestroyedOnTime` | The key of epoch `k` is destroyed before epoch `k + 3` begins.         |
| `KeysAvailable`       | While the node runs, every worker holds the keys of the current and the next epoch. |
| `TypeOK`              | Type invariant.                                                        |

`KeysDestroyedOnTime` is the forward secrecy property. A key is last usable
in epoch `k + 1`, and the publish step of epoch `k + 2` prunes it. A key
counts as existing while the node, a worker or a file holds it.

Without restarts, `ReplayFreedom` holds by construction. A packet is accepted
only if its tag is new to the filter, accepting it records the tag, and the
filter never shrinks. In that setting the invariant documents the mechanism
and is not evidence about the code. With restarts it can fail, and does.

## Results

| Model     | Config             | Expected result                | Distinct states |
|-----------|--------------------|--------------------------------|-----------------|
| `MixNode` | `Pipeline`         | all six invariants hold        | 6,591,120       |
| `MixNode` | `WitnessSent`      | `NeverSent` violated           |                 |
| `MixNode` | `WitnessDelivered` | `NeverDelivered` violated      |                 |
| `MixNode` | `WitnessShortened` | `NeverShortened` violated      |                 |
| `MixKeys` | `Healthy`          | all four invariants hold       | 44,184          |
| `MixKeys` | `OneSkip`          | three invariants hold          | 121,328         |
| `MixKeys` | `OneSkipSecrecy`   | `KeysDestroyedOnTime` violated |                 |
| `MixKeys` | `TwoSkips`         | `KeysAvailable` violated       |                 |
| `MixKeys` | `Restart`          | two invariants hold            | 113             |
| `MixKeys` | `RestartReplay`    | `ReplayFreedom` violated       |                 |
| `MixKeys` | `RestartSecrecy`   | `KeysDestroyedOnTime` violated |                 |
| `MixKeys` | `WitnessAccepts`   | `NeverAccepts` violated        |                 |
| `MixKeys` | `WitnessDestroys`  | `NeverDestroys` violated       |                 |

Each file is named `<Model>_<Config>.cfg`. State counts are from TLC 2.19.
TLC stops at the first counterexample, so a failing configuration has no
meaningful count. The invariants whose names begin with `Never` are expected
to fail. Each exists to produce a witness trace.

| Constants of `MixNode` | Value | | Constants of `MixKeys` | Value |
|------------------------|-------|-|------------------------|-------|
| `Packets`              | 2     | | `Workers`              | 2     |
| `MaxTick`              | 5     | | `Tags`                 | 2, or none |
| `UnwrapDelay`          | 2     | | `MaxEpoch`             | 6     |
| `SchedulerSlack`       | 1     | | `MaxSkips`             | 0, 1 or 2 |
| `MaxDelay`             | 3     | | `Restarts`             | yes or no |

`Restart` and `RestartSecrecy` run with no tags, and so with no packets.
Whether a key exists does not depend on packets, and with restarts they
multiply the states beyond what can be searched.

## What the models show

**The pipeline does what it is meant to.** All properties hold for all three
roles, with the connection to the next hop coming and going at will.

**A packet may spend less than its delay in the scheduler.** It never spends
less than its delay in the node. `WitnessShortened` shows a packet that
waited for a crypto worker and was then held for less than the delay its
sender asked for. `MinimumMixing` shows that the two together are never less
than that delay.

**Forward secrecy depends on the publish step.** `Prune` has one call site,
inside `publishDescriptorIfNeeded`. If an epoch passes without that step,
nothing is pruned in that epoch. `OneSkipSecrecy` shows the result:

1. The node publishes in epochs 1 and 2.
2. Epoch 3 passes without the publish step.
3. Epoch 4 begins. The key of epoch 1 still exists. It should have been
   pruned in epoch 3.

**The supply of keys depends on it too.** Apart from start-up, `Generate` has
the same single call site. One skipped epoch does no harm, as `OneSkip`
shows. After two in a row the node has no key for the next epoch, as
`TwoSkips` shows. After three it would have none for the current epoch, and
would refuse every packet.

Both findings were read from the code and checked in the model. They were not
reproduced by running the server.

**A restart with saved keys lets a packet through twice.** `RestartReplay`
shows it:

1. A worker accepts a packet under the key of epoch 1.
2. The node shuts down cleanly. The key is written to a file.
3. The node boots and loads the key. Its replay filter is new and empty.
4. A worker accepts the same packet again.

`Persist` writes the private key. `Load` builds the key around a fresh
filter. Anyone who recorded a packet before the restart can send it again
afterwards, for as long as the key is tried, and the node will process it as
new. In the model, saving the filter with the key restores the property.

This one was replayed against the server code. The test is in
[`mixkey_replay_repro_test.go.txt`](mixkey_replay_repro_test.go.txt), with
instructions at the top. It passes when the problem is present: the loaded
key is the same key, and it accepts a tag it had already seen.

The option is off by default. The code comments say why: a node that starts
with fresh keys has forward secrecy across the restart.

**Saved keys outlive their epoch while the node is down.** `RestartSecrecy`
shows a node that shuts down in epoch 1 and is still down in epoch 4, with
the key of epoch 1 on disk. The files are removed at the next boot, not
before. By default they are kept in memory-backed storage, so they do not
survive the machine being switched off.

## What is not checked

Two rules are in the models because the code has them, but no invariant
depends on them. A mutation test confirmed that for each.

- **The three keys a worker tries.** Widening that to every key the worker
  holds breaks no invariant.
- **Dropping a packet that asked for no delay and still had to wait.**
  Keeping such a packet breaks no invariant. It would still be held for one
  tick.

## What is not modelled

- **Cryptography.** A packet unwraps under the key of its epoch and no other.
- **The Bloom filter.** The replay filter is exact. The real one may also
  reject a fresh tag.
- **A restart without saved keys, and a crash.** The node then begins with
  fresh keys, which no earlier packet unwraps under.
- **A full replay filter.** The code then treats every further packet for
  that key as a replay.
- **A clock that goes backwards.**
- **Slow workers.** Every worker copies the key set within the epoch in which
  it was told to.
- **Decoy packets the node creates.** The code hands them straight to the
  outgoing connection. They do not pass through the scheduler.
- **Limits.** The rate limit on clients, the size limit of the scheduler
  queue, the burst limit, and a delay limit taken from the PKI document.
- **The scheduler's own check of the delay.** Without a limit from the PKI
  document it cannot fail, because the crypto worker has applied the same
  bound.
- **The backends.** Where a packet goes after it reaches the gateway, the
  service node or the decoy handler.
- **Liveness.** Only invariants are checked.

## How the invariants were tested

Each invariant that is expected to hold was mutation-tested. An error was
introduced into a copy of the specification and TLC reported the violation.

| Mutation                                          | Caught by               |
|---------------------------------------------------|-------------------------|
| The wait is taken off the delay twice             | `MinimumMixing`         |
| A packet may be handed over with no delay         | `MinimumMixing`         |
| A packet may be sent before it is due             | `MinimumMixing`         |
| A packet from a client may be delivered locally   | `ClientPacketsAreMixed` |
| A service node forwards what a mix gave it        | `ServiceNodeTerminates` |
| A mix delivers to a backend                       | `MixHasNoBackend`       |
| Any SURB reply reaches the decoy handler          | `PlaceMatchesCommand`   |
| An accepted tag is not recorded                   | `ReplayFreedom`         |
| Keys are pruned one epoch later                   | `KeysDestroyedOnTime`   |
| A worker never lets go of a key                   | `KeysDestroyedOnTime`   |
| Only one key is generated ahead                   | `KeysAvailable`         |
| Keys are pruned two epochs early                  | `KeysAvailable`         |
| A boot loads every file and makes no new key      | `KeysAvailable`         |

The constants matter. With a longest delay of 2 ticks and a longest wait of
1, the first mutation went unnoticed. The configurations use 3 and 2 for that
reason.

## Running

Requires Java and `tla2tools.jar` (TLC). Download it from
<https://github.com/tlaplus/tlaplus/releases> into this directory, or point
`TLA2TOOLS` at it. Do not commit the jar.

```sh
./check.sh
```

runs every configuration and compares each result with the expected one. It
exits non-zero if any differs. The suite takes under a minute on a 12-core
machine.

To run one configuration and read its trace:

```sh
java -jar tla2tools.jar -config MixKeys_OneSkipSecrecy.cfg MixKeys.tla
```
