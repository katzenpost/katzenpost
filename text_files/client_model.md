# The client ARQ and its TLA+ model

This document has three parts. The first explains how the client daemon
sends a query reliably. The second describes the TLA+ model of that
mechanism. The rest records a review of the model: what was changed, what the
model checker found, and what the results do and do not establish.

The implementation is in [`client/arq.go`](../client/arq.go),
[`client/daemon.go`](../client/daemon.go) and
[`client/pigeonhole.go`](../client/pigeonhole.go). The model is in
[`client/tla/`](../client/tla/).

The document describes the code as it is on `main` at commit `91debb674`.
The changes to the model are in the working tree and are not committed.

## How the client ARQ works

### The daemon and its thin clients

Applications do not talk to the mixnet directly. Each one links a thin client
library and connects to a single client daemon. The daemon does all the
mixnet cryptography: it composes Sphinx packets, decrypts replies, and keeps
the PKI document up to date. It multiplexes every application onto one
connection to a gateway node.

An application reads and writes Pigeonhole storage by sending a query to a
courier service in the mixnet. The mixnet may lose the query or the reply.
The ARQ is the part of the daemon that repeats a query until it is answered.
ARQ stands for automatic repeat request.

### An operation

An application starts an operation with `StartResendingEncryptedMessage`. The
request carries an encrypted query, an envelope hash that identifies it, and
either a read capability or a write capability.

The daemon picks a courier at random from the PKI document and keeps using
that courier for every retry of the operation. It then creates an
`ARQMessage` and tracks it in two maps:

| Map                  | From          | To           | Used by              |
|----------------------|---------------|--------------|----------------------|
| `arqSurbIDMap`       | SURB id       | the message  | replies and resends  |
| `arqEnvelopeHashMap` | envelope hash | SURB id      | cancellation         |

An operation is live exactly as long as it is in these maps. It ends in one
of three ways: a reply completes it, the application cancels it, or the
application's session is destroyed. There is no retry limit.

### SURBs

A reply travels back on a SURB, a single-use reply block. The daemon puts a
fresh SURB in every query it sends. Each SURB has a random id and its own
decryption keys, and the daemon stores both in the `ARQMessage`.

Every re-send therefore replaces the SURB id and the keys. The code calls
this rotation. After a rotation the old id is no longer in the map, so a
reply to an earlier copy of the query matches nothing and is discarded.

### Sending and re-sending

1. **First send.** `arqSend` composes the packet, registers the operation in
   both maps, arms a retry timer, and sends. The timer is set to the expected
   round trip time plus 20 seconds.
2. **The timer fires.** `enqueueResend` puts the SURB id on the resend queue
   of the application's connection. If the application has no connection at
   that moment, it arms the timer again instead, to try a little later.
3. **The resend runs.** The egress worker sends at a paced rate and takes
   resends before new requests. `arqDoResend` looks the operation up by that
   SURB id, rotates it, arms a new timer, and sends.

A failed send is logged and otherwise ignored. The timer is already armed,
so the operation is retried in any case.

### Handling a reply

`handleReply` looks the reply's SURB id up in the map. If it finds an
operation it cancels that operation's retry timer and passes the operation
and the reply to `handlePigeonholeARQReply`. It does not remove the operation
from the maps.

The handler decrypts the reply with the operation's keys and applies a state
machine, `computeARQStateTransition`. An operation is in one of two live
states, waiting for an ACK or ACK received.

| State           | Reply               | Operation             | Action                          |
|-----------------|---------------------|-----------------------|---------------------------------|
| any             | carries an error    | any                   | answer with the error           |
| waiting for ACK | ACK                 | default write         | answer with success             |
| waiting for ACK | ACK                 | read, or strict write | go to ACK received, send again  |
| ACK received    | ACK                 | any                   | send again                      |
| either          | payload             | any                   | process the payload             |

A default write is idempotent: the ACK alone completes it. A strict write is
one with `NoIdempotentBoxAlreadyExists` set. It needs a payload reply, as a
read does.

Processing a payload has four outcomes.

| The payload                                 | Action                                        |
|---------------------------------------------|-----------------------------------------------|
| decrypts                                    | answer with success, and the data for a read  |
| says the box was not found, on a read       | send again, and go back to waiting for ACK    |
| says the box already exists, on a default write | answer with success                       |
| fails in any other way                      | answer with the error                         |

"Send again" means that the handler sets the new state and queues a resend,
in `scheduleARQFollowUp`. It does not send anything itself. The egress worker
picks the resend up on its next tick and rotates the operation then. A
follow-up therefore leaves at a time the scheduler chose, and an observer
cannot tell it from other traffic by how soon it follows the reply.

"Answer" always means removing the operation from both maps and sending one
`StartResendingEncryptedMessageReply` to the application.

### Cancelling

The application cancels with `CancelResendingEncryptedMessage`, naming the
envelope hash. If the operation is still tracked, the daemon removes it,
cancels its timer, and sends two replies: a Cancelled error to the original
call, and success to the cancel call. If the operation is no longer tracked,
only the cancel call is answered.

### Losing the connection

This is about the application's connection to the daemon, not the daemon's
connection to the gateway.

| How the connection ends                       | What happens to its operations                         |
|-----------------------------------------------|--------------------------------------------------------|
| the application closes it explicitly          | `cleanupForAppID` removes them at once                 |
| it drops, and the client has a session token  | they are kept for a grace period, 10 minutes by default |
| it drops, and the client has no session token | `cleanupForAppID` removes them at once                 |

A client with a session token may reconnect within the grace period and
resume its session. If it does not, the grace period ends with
`cleanupForAppID`.

### Who runs what

The daemon touches an operation from three goroutines and a timer.

| Goroutine          | Does                                | Code                                    |
|--------------------|-------------------------------------|-----------------------------------------|
| ingress worker     | looks up and handles replies        | `handleReply`, `handlePigeonholeARQReply` |
| egress worker      | starts operations, runs resends     | `arqSend`, `arqDoResend`                |
| thin-client reader | cancels                             | `cancelResendingEncryptedMessage`       |
| timer queue        | queues resends                      | `enqueueResend`                         |

They share the two maps under one lock, `replyLock`. The lock is held for
each access to the maps, and not for a whole operation. The ingress worker
takes the lock to look a reply up, releases it, and takes it again later to
remove the operation or to queue a follow-up. Between those two moments the
other goroutines may run.

One guard exists for that gap. Only the egress worker rotates, and it looks
the operation up under the lock first. A rotation therefore cannot bring a
cancelled operation back.

## The model

### What a model checker does here

The model is a TLA+ specification, checked with TLC. It describes the
mechanism as a set of states and the steps that lead from one to the next.
TLC visits every reachable state, for a small number of operations, and
checks that a stated property holds in each one. If a property fails, TLC
prints the steps that led there.

This suits the ARQ well. Its correctness depends on the order in which three
goroutines act, and TLC tries every order. A test tries one.

### Parameters

| Constant      | Meaning                                                 |
|---------------|---------------------------------------------------------|
| `Msgs`        | the operations                                          |
| `MaxRetx`     | the most rotations an operation may have                |
| `Atomic`      | if true, nothing runs between looking a reply up and handling it |
| `Disconnects` | if true, the application may disconnect                 |

The two switches exist for comparison. With `Atomic` true and `Disconnects`
false the model describes the protocol alone. Turning one switch shows what
that feature adds.

### State

| Variable   | Holds                                                           |
|------------|-----------------------------------------------------------------|
| `conn`     | the session: up, away within the grace period, or closed        |
| `op`       | one record per operation                                        |
| `handling` | the reply the ingress worker has looked up and not yet handled  |

The record of an operation:

| Field       | Holds                                                     |
|-------------|-----------------------------------------------------------|
| `kind`      | read, default write, or strict write                      |
| `started`   | the application started it                                |
| `tracked`   | it is in the ARQ maps                                     |
| `cancelled` | the application cancelled it                              |
| `fsm`       | waiting for ACK, or ACK received                          |
| `gen`       | the generation of its current SURB                        |
| `timer`     | a retry timer is armed for the current SURB               |
| `resendQ`   | the SURB ids waiting on the resend queue                  |
| `answered`  | the queries whose reply has arrived                       |
| `responses` | how many replies the application was sent, up to 2        |
| `doneBy`    | what caused the latest of them                            |

A SURB id is modelled as the pair of an operation and a generation. Every
rotation adds one to the generation. That makes the old id stale and stands
for the change of keys as well.

### Steps

| Step         | What happens                                                        | Code it stands for                  |
|--------------|---------------------------------------------------------------------|-------------------------------------|
| `Start`      | The operation is tracked and its timer armed.                       | `arqSend`                           |
| `Cancel`     | The operation is removed. The original call is answered if it was tracked. | `cancelResendingEncryptedMessage` |
| `TimerFire`  | The current SURB id is queued for resend. With no connection the timer is armed again. | `enqueueResend`  |
| `DoResend`   | The operation is rotated, or deleted if there is no connection.     | `arqDoResend`                       |
| `Lookup`     | A reply arrives. If it matches, the timer is cancelled and the worker holds the operation. | `handleReply`     |
| `Handle`     | The worker decrypts, applies the state machine, and answers or queues a follow-up. | `handlePigeonholeARQReply`, `handlePayloadReply`, `scheduleARQFollowUp` |
| `Disconnect` | The session goes away, keeping its state.                           | `onClosedConn`                      |
| `Resume`     | The session comes back.                                             | `handleSessionToken`                |
| `Cleanup`    | The session is closed and every operation removed.                  | `cleanupForAppID`                   |

`Lookup` and `Handle` are separate steps because the code releases the lock
between them. `Handle` follows the code in two details that matter:

- It decrypts with the keys the operation holds when `Handle` runs. If the
  operation was rotated after `Lookup`, decryption fails and the operation is
  deleted.
- It answers without checking that the operation is still tracked.

### The network and the courier

Both are adversarial. Any query sent so far may be answered, once, with any
kind of reply, at any time or never. A lost query and a lost reply are both a
reply that never arrives. The model needs no separate step for loss.

### What the model checks

| Invariant               | Statement                                                              |
|-------------------------|------------------------------------------------------------------------|
| `AtMostOneResponse`     | The application receives at most one reply per operation.              |
| `NoSilentDrop`          | An operation is never forgotten without a reply, while the session lives. |
| `NoOrphan`              | A tracked operation of a connected client can still make progress.     |
| `CancelIsFinal`         | A cancelled operation is never tracked again.                          |
| `NoStrayTimer`          | An operation that is not tracked has no armed timer.                   |
| `CompletionMatchesKind` | Only a default write completes on an ACK. A read retries when the box is not found. |
| `TypeOK`                | Type invariant.                                                        |

The specification is about 155 lines of TLA+ and runs in ten configurations.
What it leaves out is listed under [Limits](#limits).

## Review and changes

### Starting point

The model as found had one configuration and seven invariants. TLC reported
no violation over 17,672 states, as its README said.

The review compared the specification with the code, and tested whether the
invariants could fail at all.

### Problems found

1. **Every step was atomic.** A reply was looked up and applied in one step.
   The code does this in two, on one of three goroutines.
2. **A stale reply could not occur.** Every rotation discarded the reply in
   flight. An invariant added for the purpose confirmed that no reachable
   state held a stale reply.
3. **The SURB id check was untested.** With the check removed from the
   specification, all seven invariants still passed, over the same 17,672
   states. The README named stale replies as a key result.
4. **A cancel sent no reply.** The code answers the original call with a
   Cancelled error. The model did not count it, so two replies to one call
   could not be expressed.
5. **Disconnection was described wrongly.** The model stated that operations
   survive a disconnect and resume. It did not distinguish the application's
   connection from the gateway's, and the code deletes or strands operations
   in several cases.
6. **Four of the seven invariants could not fail.** `CompletedReportedOnce`
   and `DoneImpliesReported` restated the step that set them. `RetxBounded`
   was implied by `TypeOK`. `NoPendingWhenTerminal` held by construction.
7. **Nothing tested the state machine.** The rules for each kind of operation
   were transcribed, and no invariant depended on them.

### Changes to the specification

| Area               | Before                              | After                                                  |
|--------------------|-------------------------------------|--------------------------------------------------------|
| Reply handling     | one step                            | `Lookup` and `Handle`, with a switch to join them      |
| Replies in flight  | one slot, cleared on rotation       | any earlier query may still be answered, once          |
| Keys               | not modelled                        | tied to the generation; a rotated operation fails to decrypt |
| Retry timer        | not modelled                        | armed, fired, cancelled                                |
| Resend queue       | not modelled                        | holds SURB ids, which may go stale                     |
| Cancel             | silent                              | answers the original call if the operation was tracked |
| Connection         | one flag, toggled freely            | up, away, closed, behind a switch                      |
| Box not found      | not modelled                        | a read asks for another round and returns to waiting for ACK |
| Reply count        | counted successes and errors        | counts every reply to the application                  |
| End of a run       | a stuttering step                   | deadlock checking is turned off in the configurations  |

### Simplification pass

After those changes the specification was reviewed for anything that could
be removed. It went from 202 lines of TLA+ to 154, not counting comments and
blank lines.

| Removed or simplified                         | Why it is safe                                        |
|-----------------------------------------------|-------------------------------------------------------|
| Eleven variables, one per field               | They are now one record per operation.                |
| The lists of unchanged variables              | An action names only what it changes.                 |
| Two connection flags                          | One variable with three values. The fourth combination could not occur. |
| Helper steps that set several variables       | They are now functions from a record to a record.     |

The rewrite does not change behaviour. For the three configurations that are
searched exhaustively, the number of distinct states and the number of
transitions are identical before and after.

### Changes to the properties

| Invariant               | Status   | Note                                                   |
|-------------------------|----------|--------------------------------------------------------|
| `AtMostOneResponse`     | replaces `AtMostOnce` | Now counts the Cancelled reply.           |
| `CancelIsFinal`         | restated | Was about the reply count. Is now about tracking.      |
| `NoSilentDrop`          | new      |                                                        |
| `NoOrphan`              | new      |                                                        |
| `NoStrayTimer`          | new      |                                                        |
| `CompletionMatchesKind` | new      |                                                        |
| `NeverCompletes`        | new      | Expected to fail. Witness of a normal completion.      |
| `NeverStale`            | new      | Expected to fail. Witness of a stale reply.            |
| `CompletedReportedOnce`, `DoneImpliesReported`, `RetxBounded`, `NoPendingWhenTerminal` | removed | Could not fail. |

Every invariant that is expected to hold was mutation-tested. An error was
introduced into a copy of the specification and TLC reported the violation.

| Mutation                                           | Caught by                        |
|----------------------------------------------------|----------------------------------|
| A resend rotates without looking the operation up  | `CancelIsFinal`                  |
| A cancel always answers the original call          | `AtMostOneResponse`              |
| A reply matches any SURB id of the operation       | `NoSilentDrop`                   |
| A rotation does not arm the timer                  | `NoOrphan`                       |
| A follow-up is not queued                          | `NoOrphan`                       |
| A cancel leaves the timer armed                    | `NoStrayTimer`                   |
| A read completes on an ACK                         | `CompletionMatchesKind`          |
| A read gives up when the box is not found          | `CompletionMatchesKind`          |
| A default write never completes on an ACK          | `WitnessCompletes` stops failing |

### Update after merging main

The model was first written against the branch point, commit `f4c37a3d`.
Main then moved by 654 commits, and the ARQ code changed in three ways that
matter here.

| Change on main                                            | Effect on the model                              |
|-----------------------------------------------------------|--------------------------------------------------|
| `enqueueResend` arms the timer again when there is no connection | `TimerFire` does the same                |
| The handler queues a follow-up and does not rotate        | `Handle` queues a resend. Only `DoResend` rotates. |
| The SACK controller was removed                           | One entry fewer under what is not modelled       |

Both steps now share one definition, `Enqueued`, which follows
`enqueueResend`.

One correction came out of the mutation tests. Rotating enters the operation
in both maps under its new id, and the model did not say so. Without that,
the model could not express a rotation that undoes a cancel, and removing the
lookup from `DoResend` went unnoticed. `Rotated` now marks the operation as
tracked. With the lookup in place this changes nothing: the state and
transition counts were identical before and after.

Every configuration keeps its expected result. What changed is how one of
them fails. `DisconnectOrphan` used to fail on a timer that fired while the
application was away. That is fixed on main. It now fails on a reply that
arrives while the application is away.

The Go replays were updated to match. The one for the timer now checks that
the timer is armed again, and two were added: the reply that arrives while
the application is away, and the follow-up that is queued.

The test harness had two faults of its own, found when one replay gave
different answers on different runs. It acted on a timer before the timer
queue had taken it, since the queue accepts a push through a channel, and it
gave the queue a stand-in callback instead of the daemon's own. Both are
fixed. The harness now waits for the queue to settle, and a timer that fires
runs `enqueueResend` as it does in the daemon.

## Configurations and results

The single configuration `ClientARQ.cfg` is deleted. Ten replace it. Each has
two operations and at most two rotations per operation.

| Config             | `Atomic` | `Disconnects` | Result                       | Distinct states |
|--------------------|----------|---------------|------------------------------|-----------------|
| `Sequential`       | yes      | no            | all seven invariants hold    | 282,263         |
| `Concurrent`       | no       | no            | four invariants hold         | 1,127,906       |
| `Disconnect`       | yes      | yes           | five invariants hold         | 1,092,974       |
| `RaceCancel`       | no       | no            | `AtMostOneResponse` violated |                 |
| `RaceResend`       | no       | no            | `NoSilentDrop` violated      |                 |
| `RaceTimer`        | no       | no            | `NoStrayTimer` violated      |                 |
| `DisconnectOrphan` | yes      | yes           | `NoOrphan` violated          |                 |
| `DisconnectDrop`   | yes      | yes           | `NoSilentDrop` violated      |                 |
| `WitnessCompletes` | yes      | no            | `NeverCompletes` violated    |                 |
| `WitnessStale`     | yes      | no            | `NeverStale` violated        |                 |

Every result matches its expectation. TLC stops at the first counterexample,
so a failing configuration has no meaningful state count.

Which invariant holds where:

| Invariant               | Protocol alone | With concurrency | With disconnects |
|-------------------------|----------------|------------------|------------------|
| `AtMostOneResponse`     | holds          | violated         | holds            |
| `NoSilentDrop`          | holds          | violated         | violated         |
| `NoOrphan`              | holds          | holds            | violated         |
| `CancelIsFinal`         | holds          | holds            | holds            |
| `NoStrayTimer`          | holds          | violated         | holds            |
| `CompletionMatchesKind` | holds          | holds            | holds            |

## What the model shows about the client

**The protocol is sound.** With atomic reply handling and a connected
application, every property holds.

**The lookup before a rotation works.** `CancelIsFinal` holds with full
concurrency, and fails when the lookup is removed from the model.

**A cancel racing a reply produces two replies.**

1. The ingress worker looks up a reply and finds the operation.
2. The application cancels. The original call is answered with a Cancelled
   error.
3. The ingress worker reaches a terminal outcome and answers the original
   call again.

The terminal branches of the handler remove the operation and answer without
checking that it is still tracked.

**A resend racing a reply loses the operation.**

1. The retry timer fires and the resend is queued.
2. A late reply arrives. The ingress worker finds the operation.
3. The egress worker runs the resend, which gives the operation fresh keys.
4. The ingress worker decrypts with those keys. They are the wrong keys.
   Decryption fails and `dropARQMessage` deletes the operation.

The application is never answered and nothing retries.

**A disconnect within the grace period strands operations.** While the
application is away:

- A reply arrives. `handleReply` cancels the timer, and the handler finds no
  connection and returns. The operation stays tracked and is never re-sent.
- A queued resend runs. `arqDoResend` finds no connection and deletes the
  operation.

After the application resumes, the operation is stuck or gone.

A timer that fires while the application is away does no harm on main. It is
armed again, and the resend is queued once the application is back.

## Confirmation in the Go code

Three problems were replayed against the daemon code on main, by calling the
real functions in the order the model found.

| Problem                           | Model predicts                      | Go code does                        |
|-----------------------------------|-------------------------------------|-------------------------------------|
| Cancel racing a reply             | two replies to one call             | Cancelled, then Success             |
| Resend racing a reply             | no reply, operation deleted         | no reply, both maps empty           |
| Reply arriving while disconnected | tracked, no resend queued, no timer | tracked, no resend queued, no timer |

Three more replays check behaviour that is not a problem.

| Behaviour                       | Model predicts                                | Go code does |
|---------------------------------|-----------------------------------------------|--------------|
| Nothing in between              | one reply                                     | the same     |
| Timer firing while disconnected | timer armed again, resend queued after resume | the same     |
| A read receives its ACK         | resend queued, SURB id unchanged              | the same     |

The replays were run three times with the same result each time.

The deletion in `arqDoResend` was read from the code and not replayed.

## Supporting files

All in [`client/tla/`](../client/tla/):

- [`ClientARQ.tla`](../client/tla/ClientARQ.tla), the specification.
- Ten files named `ClientARQ_<Config>.cfg`.
- [`check.sh`](../client/tla/check.sh) runs every configuration, compares the
  result with the expected one, and exits non-zero on any difference. The
  suite takes under a minute on a 12-core machine.
- [`README.md`](../client/tla/README.md) describes the model and explains
  each trace.
- [`arq_race_repro_test.go.txt`](../client/tla/arq_race_repro_test.go.txt)
  holds the Go tests, with instructions at the top. The suffix keeps it from
  being compiled. Each test passes when the code behaves as the model says.
  For three of them that means a problem is present, so they are evidence
  and not regression tests.

```sh
cd client/tla
./check.sh
```

`tla2tools.jar` must be in that directory or named by `TLA2TOOLS`. It is not
committed.

## Limits

- **The Go tests replay one ordering on one goroutine.** They show what the
  code does for that ordering, and not how often it occurs. The two races
  need a reply to arrive within a narrow window, so they are likely to be
  rare.
- **The effect on applications was not examined.** Whether the thin client
  library tolerates a second reply to one call is not known.
- **Rotation is bounded.** At the bound a resend arms the timer without
  rotating, so the races are explored only below the bound.
- **The gateway connection is not modelled.** A failed send is a lost query.
- **Timing is not modelled.** A timer may fire at any moment it is armed.
- **One flag is not modelled.** With `NoRetryOnBoxIDNotFound` a read does not
  retry. In the model a read always retries.
- **Not modelled:** copy commands, a full resend queue, and a failed packet
  composition. The last two arm the timer again in the code.
- **Only safety is checked.** `NoOrphan` is the closest substitute for
  liveness. It says that progress is still possible, and not that it happens.
