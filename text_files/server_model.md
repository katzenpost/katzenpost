# The mix server and its TLA+ models

This document has three parts. The first explains how a Katzenpost mix node
handles a packet and manages its keys. The second describes the two TLA+
models of it. The rest records a review of the model that was there before:
what was changed, what the model checker found, and what the results do and
do not establish.

The implementation is in the [`server`](../server/) package, mostly under
[`server/internal/`](../server/internal/). The models are in
[`server/tla/`](../server/tla/).

The document describes the code as it is on `main` at commit `91debb674`.
The changes to the models are in the working tree and are not committed.

## How the mix server works

### What a node does

A mix node receives Sphinx packets, removes one layer of encryption from
each, holds the packet for a delay its sender chose, and sends it on. The
delay is what mixes the traffic: packets leave in a different order from the
one they arrived in.

The same program runs in three roles.

| Role         | Accepts clients | Has a local backend             |
|--------------|-----------------|---------------------------------|
| mix          | no              | no                              |
| gateway      | yes             | yes, the users' message spools  |
| service node | no              | yes, the services it runs       |

### The path of a packet

```
incoming connection -> crypto worker -> scheduler -> outgoing connection
```

| Stage               | Does                                              | Code                              |
|---------------------|---------------------------------------------------|-----------------------------------|
| incoming connection | stamps the packet and queues it                   | `internal/incoming`, `onSendPacket` |
| crypto worker       | unwraps it, checks for replay, decides its route  | `internal/cryptoworker`           |
| scheduler           | holds it until its delay has passed               | `internal/scheduler`              |
| outgoing connection | sends it to the next hop                          | `internal/outgoing`               |

### Arrival

The incoming connection knows whether its peer is a client or a mix. It
records that on the packet as two flags.

| Flag            | Set when                                          | Meaning                        |
|-----------------|---------------------------------------------------|--------------------------------|
| `MustForward`   | the packet came from a client                     | it may only be sent on         |
| `MustTerminate` | this is a service node and the packet came from a mix | it may only end here       |

The first flag stops a client from reaching a local user or service without
passing through the mixnet. The second stops the last layer from sending
traffic back into it.

The connection also records the arrival time, and puts the packet on a queue
shared by all crypto workers.

### Unwrapping

There is one crypto worker per processor by default. A worker takes a packet
from the queue and works through these steps.

1. **Too old.** If the packet waited longer than `UnwrapDelay`, 250 ms by
   default, it is dropped unseen. This sheds load when the node is behind.
2. **Keys.** The worker needs the key of the current epoch. It tries that
   key, then the key of the previous epoch, then the key of the next. A
   packet unwraps under at most one of them.
3. **Replay.** Unwrapping yields a tag. If the key has seen the tag before,
   the packet is dropped.
4. **Route.** See below.

### Routing

`routePacket` decides where an unwrapped packet goes.

| The packet is           | On a         | From a  | Outcome                     |
|-------------------------|--------------|---------|-----------------------------|
| for another node        | service node | mix     | dropped                     |
| for another node        | any other case |       | to the scheduler            |
| a reply to its own decoy| mix          | mix     | to the decoy handler        |
| anything else           | mix          | mix     | dropped                     |
| not for another node    | gateway      | client  | dropped                     |
| a reply to its own decoy| gateway or service node | mix | to the decoy handler |
| anything else           | gateway or service node | mix | to the local backend |

### The delay

A packet for another node carries the delay its sender asked for. The crypto
worker takes the time the packet waited in its queue off that delay, so that
the wait counts as part of the mixing.

| Delay asked for               | Handed to the scheduler          |
|-------------------------------|----------------------------------|
| more than three epochs        | the packet is dropped            |
| more than the wait            | the delay, less the wait         |
| not more than the wait        | 1 ms                             |
| none, and the wait was under 1 ms | 1 ms, less the wait          |
| none, and the wait was longer | the packet is dropped            |

A packet is never handed over with no delay at all, so some mixing always
happens.

### The scheduler

One goroutine runs the scheduler. When a packet arrives from a crypto worker
it checks two things: that the delay is within the limit, and that there is a
connection to the next hop. It then puts the packet in a queue ordered by the
time it is due.

When a packet is due the scheduler takes it from the queue. If it is late by
more than `SchedulerSlack`, 450 ms by default, the packet is dropped. A node
that cannot keep its timing does not send stale packets.

### Sending

The outgoing side looks the next hop up again. If the connection has gone in
the meantime, the packet is dropped.

### Mix keys

A mix key belongs to one epoch. An epoch lasts 20 minutes by default. The
node publishes its keys in its descriptor, which the directory authorities
put in the consensus.

The PKI worker prepares the descriptor for the next epoch once per epoch, in
`publishDescriptorIfNeeded`. It must do so early: the window is about the
first two minutes of the epoch. The same step manages the keys.

1. **Generate.** It makes sure there are keys for the next three epochs.
2. **Prune.** It removes every key older than the previous epoch.
3. **Reshadow.** If anything changed, it tells each crypto worker to copy the
   key set again. The call waits for each worker in turn.

Apart from start-up, generating and pruning happen nowhere else. So an epoch
in which the step does not run is an epoch without either. That happens when
the upload window has closed, when the step fails early, and when the node
has stopped advertising itself. The last is deliberate: with
`WaitForConsensusExitOnShutdown`, a node that is asked to stop keeps serving
traffic until it has left the consensus, which can take about 40 minutes.

The life of the key of epoch `k`:

| During epoch       | The key is                                    |
|--------------------|-----------------------------------------------|
| `k - 3`            | generated                                     |
| `k - 1`, `k`, `k + 1` | tried by the crypto workers                |
| `k + 2`            | pruned, early in the epoch                    |

A key is counted by its holders: the node, and each crypto worker that has
copied it. It is destroyed when the last holder lets go. Pruning is how the
node lets go. Copying the key set again is how a worker does.

This is what gives the node forward secrecy. Someone who takes over the node
in epoch `k + 3` finds no key that can open traffic from epoch `k`. That
holds as long as the publish step runs every epoch and, when keys are saved
on shutdown, as long as the node is running.

By default keys are not stored on disk, and a node that restarts begins with
fresh keys. Its published keys are then wrong until the next consensus, and
clients cannot reach it for about an epoch.

The option `PersistMixKeysOnShutdown` avoids that. On a clean shutdown the
node writes every key to a file. On the next boot it loads the files of the
current epoch and the two after it, and removes every other file. A file is
removed as soon as it is loaded. By default the files are kept in
memory-backed storage. A crash writes nothing.

### Replay protection

Each key carries a Bloom filter of the tags it has seen. All crypto workers
share it, and testing and setting a tag is one step under the key's lock.
The filter is 64 MiB and holds about 37 million tags. If it fills up, the key
treats every further packet as a replay.

The filter lives and dies with the key in memory. It is not part of a key
file. A key that is loaded from a file starts with an empty filter.

### Decoys

A node also creates decoy packets of its own, which loop through the mixnet
and come back as SURB replies. It hands them straight to the outgoing
connection. They do not pass through the crypto workers or the scheduler.
The replies do, as the routing table shows.

## The models

### What a model checker does here

Each model is a TLA+ specification, checked with TLC. It describes a
mechanism as a set of states and the steps that lead from one to the next.
TLC visits every reachable state, for a small instance, and checks that a
stated property holds in each one. If a property fails, TLC prints the steps
that led there.

### Why two models

| Model         | Covers                                                |
|---------------|-------------------------------------------------------|
| `MixNode.tla` | the path of a packet: waiting, routing, mixing, drops |
| `MixKeys.tla` | key rotation, forward secrecy and replay protection   |

The two mechanisms barely interact. The pipeline needs to know one thing
about keys: whether a packet unwrapped. One model of both would multiply
their states for no gain.

### The pipeline model

| Constant         | Meaning                                          |
|------------------|--------------------------------------------------|
| `Packets`        | the packets                                      |
| `MaxTick`        | the last tick to explore                         |
| `UnwrapDelay`    | the longest wait for a crypto worker             |
| `SchedulerSlack` | the lateness tolerated when a packet is due      |
| `MaxDelay`       | the longest delay accepted                       |

Time is a counter of ticks. One tick stands for one millisecond.

| Variable | Holds                                       |
|----------|---------------------------------------------|
| `now`    | the clock                                   |
| `role`   | the role of the node                        |
| `connUp` | there is a connection to the next hop       |
| `pkt`    | one record per packet                       |

The record of a packet holds where it is, why it was dropped if it was,
whether it came from a client, what it turned out to be, the delay it asked
for, and four times: arrival, the delay given to the scheduler, when it is
due, and when it left.

| Step       | What happens                                                          |
|------------|-----------------------------------------------------------------------|
| `Arrive`   | A packet arrives. Its origin, kind and delay are chosen freely.       |
| `Unwrap`   | A crypto worker drops it, or routes it as the table above says.       |
| `Enqueue`  | The scheduler checks the next hop and queues the packet.              |
| `Dispatch` | The scheduler takes a packet that is due, and sends or drops it.      |
| `Flap`     | The connection to the next hop comes or goes.                         |
| `Tick`     | Time passes.                                                          |

The role is chosen at the start, so one run covers all three roles.

| Invariant               | Statement                                                                 |
|-------------------------|---------------------------------------------------------------------------|
| `MinimumMixing`         | A packet that is sent spent at least the requested delay in the node, and at least one tick. |
| `ClientPacketsAreMixed` | A packet from a client never reaches a local backend or the decoy handler. |
| `ServiceNodeTerminates` | A service node sends on nothing that a mix gave it.                       |
| `MixHasNoBackend`       | Nothing reaches a backend on a mix.                                       |
| `PlaceMatchesCommand`   | Only forward packets are sent on. Only decoy replies reach the decoy handler. |

### The keys model

| Constant   | Meaning                                                  |
|------------|----------------------------------------------------------|
| `Workers`  | the crypto workers                                       |
| `Tags`     | the replay tags                                          |
| `MaxEpoch` | the last epoch to explore                                |
| `MaxSkips` | how many epochs may pass without the publish step        |
| `Restarts` | whether the node may shut down and boot with its keys saved |

| Variable    | Holds                                                   |
|-------------|---------------------------------------------------------|
| `epoch`     | the current epoch                                       |
| `published` | the publish step has run in this epoch                  |
| `skips`     | how many epochs have passed without it                  |
| `keys`      | the epochs the node holds a key for                     |
| `shadow`    | each worker's copy of that set                          |
| `pending`   | the worker was told to copy again and has not yet       |
| `seen`      | the replay filter of each key                           |
| `accepts`   | how often each packet was accepted, up to 2             |
| `down`      | the node is shut down                                   |
| `files`     | the epochs with a key file on disk                      |

| Step        | What happens                                                        |
|-------------|---------------------------------------------------------------------|
| `Publish`   | Keys are generated and pruned. The workers are told.                |
| `Reshadow`  | A worker copies the key set.                                        |
| `Accept`    | A worker accepts a packet and records its tag.                      |
| `NextEpoch` | The epoch ends.                                                     |
| `Shutdown`  | The node stops cleanly. Every key goes to a file. The filters are gone. |
| `Boot`      | The node starts, loads the files it can use, and removes the rest.  |

A packet is a key epoch and a tag. It may arrive at any worker, at any time,
any number of times.

| Invariant             | Statement                                                      |
|-----------------------|----------------------------------------------------------------|
| `KeysDestroyedOnTime` | The key of epoch `k` is destroyed before epoch `k + 3` begins. |
| `KeysAvailable`       | While the node runs, every worker holds the keys of the current and the next epoch. |
| `ReplayFreedom`       | No packet is accepted twice.                                   |

`KeysDestroyedOnTime` is the forward secrecy property. A key counts as
existing while the node, a worker or a file holds it.

Without restarts, `ReplayFreedom` holds by construction. A packet is accepted
only if its tag is new to the filter, accepting it records the tag, and the
filter never shrinks. In that setting the invariant documents the mechanism
and is not evidence about the code. A restart is the one thing in the model
that empties a filter, and with restarts the invariant fails.

The specifications are 140 and 107 lines of TLA+.

## Review and changes

### Starting point

The model as found was one specification, `MixNode.tla`, with one
configuration and eight invariants. TLC reported no violation over
11,088,177 states, as its README said.

### Problems found

1. **Forward secrecy restated a guard.** The model had no key set and no
   pruning. Its unwrap step tested that the packet's epoch was within one of
   the current epoch, and the invariant asserted the same of every accepted
   packet. Whether a key still exists was not represented.
2. **Decoys were modelled wrongly.** They entered the scheduler and were
   subject to its delay check. The code hands them straight to the outgoing
   connection.
3. **Node roles were missing.** A packet for a user was always delivered. In
   the code that depends on the role of the node and on where the packet
   came from.
4. **The next hop was a fixed flag.** It was chosen once per packet and
   tested when the packet was unwrapped. The code tests the connection when
   the packet is queued and again when it is sent, and the connection can
   go away in between.
5. **The wait for a crypto worker was ignored.** The delay ran from the
   moment of unwrapping. The code takes the wait off the delay.
6. **Drop reasons did not match the code.** They could not be compared with
   the labels in the node's metrics.
7. **Six invariants restated the step that made them true.**
   `ForwardSecrecy`, `NoEarlyDispatch`, `MixingDelayBounded`,
   `ForwardedValid`, `DeliveredLocal` and `DropAccounted`.
8. **The state space was mostly waste.** The content of each packet was
   chosen in the initial state, giving 40,000 initial states.

### Changes to the specification

| Area               | Before                                | After                                                   |
|--------------------|---------------------------------------|---------------------------------------------------------|
| Structure          | one specification                     | two, one per mechanism                                  |
| Keys               | an arithmetic test on the epoch       | a key set, generated, pruned and copied by workers      |
| Key destruction    | not modelled                          | a key exists while anyone holds it                      |
| Publish step       | not modelled                          | once per epoch, and it may be skipped                   |
| Crypto workers     | one, implicit                         | several, each with its own copy of the keys             |
| Roles              | none                                  | mix, gateway, service node                              |
| Origin of a packet | none                                  | from a client or from a mix                             |
| Delay              | from the moment of unwrapping         | less the wait for a crypto worker, never under one tick |
| Next hop           | fixed per packet, tested once         | a connection that comes and goes, tested twice          |
| Decoys             | through the scheduler                 | left out, with the reason stated                        |
| Packet content     | chosen in the initial state           | chosen on arrival                                       |
| Drop reasons       | the model's own                       | the labels the code reports                             |
| End of a run       | a stuttering step                     | deadlock checking is turned off in the configurations   |

### Simplification pass

After those changes the specifications were reviewed for anything that could
be removed. Both were already compact, so there was little. The pipeline
went from 145 lines of TLA+ to 140. The keys model did not change in that
pass.

| Removed                                   | Why it is safe                                           |
|-------------------------------------------|----------------------------------------------------------|
| The scheduler's check of the delay        | It could not fail. The crypto worker applies the same bound. |
| The stored outcome of unwrapping          | It was chosen on arrival and used in one step. It is now chosen there. |

TLC confirmed that the first was dead before it was removed, and the state
and transition counts were identical afterwards. The second reduces the
state count, so the mutation tests were repeated instead, and every drop
reason was checked to be still reachable.

### Changes to the properties

| Before                                  | After                                                       |
|-----------------------------------------|-------------------------------------------------------------|
| `ForwardSecrecy`                        | `KeysDestroyedOnTime`, about the key and not its use        |
| `NoEarlyDispatch`, `MixingDelayBounded` | `MinimumMixing`, measured from arrival                      |
| `ForwardedValid`, `DeliveredLocal`      | `PlaceMatchesCommand` and the three properties about roles  |
| `ReplayFreedom`                         | kept, in the keys model                                     |
| `DropAccounted`                         | removed, it held by construction                            |
|                                         | `KeysAvailable`, new                                        |

Five further invariants are expected to fail and exist to produce a witness
trace. Their names begin with `Never`.

Every invariant that is expected to hold was mutation-tested. An error was
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

One further mutation is a repair rather than a fault. With the replay filter
saved and loaded along with the key, `ReplayFreedom` holds again in the
configuration with restarts.

Two mutations went unnoticed, which shows that no invariant depends on the
rule they broke.

| Mutation                                          | The rule is                               |
|---------------------------------------------------|-------------------------------------------|
| A worker tries every key it holds                 | transcribed from the code, and not checked |
| A packet with no delay that had to wait is kept   | transcribed from the code, and not checked |

The constants matter as well. With a longest delay of 2 ticks and a longest
wait of 1, taking the wait off twice went unnoticed. The configurations use
3 and 2 for that reason.

### Update after merging main

The models were first written against the branch point, commit `f4c37a3d`.
Main then moved by 654 commits.

**The pipeline.** The crypto worker and the scheduler did not change. Nor
did the model.

**The keys.** Three things changed on main.

| Change on main                                          | Effect on the model                                   |
|---------------------------------------------------------|-------------------------------------------------------|
| Keys can be saved on a clean shutdown and loaded on boot | new steps `Shutdown` and `Boot`, new constant `Restarts` |
| A node can stop advertising itself before it shuts down | one more reason for a skipped publish step. No change. |
| A full replay filter no longer stops the node           | noted under what is not modelled                      |

The existing configurations were not affected. Their state and transition
counts are identical before and after.

Three configurations were added for restarts. The first attempt at one of
them did not finish: once a restart can empty a filter, the count of
acceptances is no longer tied to the filter, and the states multiply. Two of
the three now run with no packets at all, which is sound because whether a
key exists does not depend on packets.

## Configurations and results

The single configuration `MixNode.cfg` is deleted. Thirteen replace it.

| Model     | Config             | Result                         | Distinct states |
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

Every result matches its expectation. The counts of invariants include
`TypeOK`. TLC stops at the first counterexample, so a failing configuration
has no meaningful state count.

The pipeline runs with two packets, five ticks, a longest wait of 2, a slack
of 1 and a longest delay of 3. The keys model runs with two workers, two
tags and six epochs. `Restart` and `RestartSecrecy` run with no tags.

## What the models show about the server

**The pipeline does what it is meant to.** All properties hold for all three
roles, with the connection to the next hop coming and going at will.

**A packet may spend less than its delay in the scheduler.** It never spends
less than its delay in the node. `WitnessShortened` shows a packet that
waited for a crypto worker and was then held for less than it asked.
`MinimumMixing` shows that the wait and the hold together are never less.

**Forward secrecy depends on the publish step.** `Prune` has one call site,
inside `publishDescriptorIfNeeded`. If an epoch passes without that step,
nothing is pruned in that epoch. `OneSkipSecrecy` shows the result.

1. The node publishes in epochs 1 and 2.
2. Epoch 3 passes without the publish step.
3. Epoch 4 begins. The key of epoch 1 still exists. It should have been
   pruned in epoch 3.

**The supply of keys depends on it too.** Apart from start-up, `Generate` has
the same single call site. One skipped epoch does no harm. After two in a row
the node has no key for the next epoch. After three it would have none for
the current epoch, and would refuse every packet.

**A restart with saved keys lets a packet through twice.** `RestartReplay`
shows it.

1. A worker accepts a packet under the key of epoch 1.
2. The node shuts down cleanly. The key is written to a file.
3. The node boots and loads the key. Its replay filter is new and empty.
4. A worker accepts the same packet again.

`Persist` writes the private key. `Load` builds the key around a fresh
filter. Anyone who recorded a packet before the restart can send it again
afterwards, for as long as the key is tried, and the node will process it as
new. In the model, saving the filter with the key restores the property.

This was replayed against the server code. The loaded key was the same key,
and it accepted a tag it had already seen.

The option is off by default, and the testnet configuration turns it on.

**Saved keys outlive their epoch while the node is down.** `RestartSecrecy`
shows a node that shuts down in epoch 1 and is still down in epoch 4, with
the key of epoch 1 on disk. The files are removed at the next boot, and not
before.

**The scheduler's check of the delay repeats one already made.** With no
limit from the PKI document, a packet that reaches the scheduler has passed
the same bound in the crypto worker. This is harmless.

## Supporting files

All in [`server/tla/`](../server/tla/):

- [`MixNode.tla`](../server/tla/MixNode.tla) and
  [`MixKeys.tla`](../server/tla/MixKeys.tla), the specifications.
- Thirteen files named `<Model>_<Config>.cfg`.
- [`mixkey_replay_repro_test.go.txt`](../server/tla/mixkey_replay_repro_test.go.txt)
  holds the Go test for the restart finding, with instructions at the top.
  The suffix keeps it from being compiled. It passes when the problem is
  present.
- [`check.sh`](../server/tla/check.sh) runs every configuration, compares the
  result with the expected one, and exits non-zero on any difference. The
  suite takes under a minute on a 12-core machine.
- [`README.md`](../server/tla/README.md) describes the models.

```sh
cd server/tla
./check.sh
```

`tla2tools.jar` must be in that directory or named by `TLA2TOOLS`. It is not
committed.

## Limits

- **Two of the findings about keys were not reproduced by running the
  server.** That forward secrecy and the supply of keys depend on the publish
  step was read from the code and checked in the model. The restart finding
  was replayed against the code.
- **How often the publish step is skipped was not assessed.** It is skipped
  when the upload window of an epoch has closed, when the step fails before
  it reaches the keys, and while a node withdraws from the consensus before
  a shutdown.
- **Without restarts, `ReplayFreedom` is not evidence about the code.** It
  holds by construction in the model.
- **Cryptography is symbolic.** A packet unwraps under the key of its epoch
  and no other.
- **The replay filter is exact.** The real one is a Bloom filter, which may
  also reject a fresh tag.
- **Not modelled:** a restart without saved keys, a crash, a full replay
  filter, and a clock that goes backwards.
- **Workers are prompt.** Every worker copies the key set within the epoch in
  which it was told to.
- **Not modelled in the pipeline:** decoy packets the node creates, a forward
  packet that unwraps with a payload, the rate limit on clients, the size
  limit of the scheduler queue, the burst limit, and a delay limit taken
  from the PKI document.
- **The backends are outside the models.** What happens to a packet after it
  reaches the gateway, the service node or the decoy handler is not covered.
- **Only safety is checked.**
