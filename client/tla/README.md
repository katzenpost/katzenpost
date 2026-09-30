# TLA+ model of the client ARQ

A formal model of the ARQ in the Katzenpost client daemon: the stop-and-wait
protocol that sends a Pigeonhole query into the mixnet and retransmits it
until a reply arrives on a SURB (single-use reply block).

The model follows [`arq.go`](../arq.go), [`daemon.go`](../daemon.go) and
[`pigeonhole.go`](../pigeonhole.go), as they are on `main` at commit
`91debb674`.

## What is modelled

An application starts an operation. The daemon sends the query with a fresh
SURB and arms a retry timer. When a reply arrives the daemon either answers
the application or sends the query again with another fresh SURB. When the
timer fires first, the daemon re-sends. The application may cancel at any
time, and may lose its connection to the daemon.

The daemon touches an operation from three goroutines and a timer. They share
the two ARQ maps under `replyLock`.

| Goroutine          | Model actions       | Code                                                   |
|--------------------|---------------------|--------------------------------------------------------|
| ingress worker     | `Lookup`, `Handle`  | `handleReply`, `handlePigeonholeARQReply`, `handlePayloadReply`, `scheduleARQFollowUp` |
| egress worker      | `Start`, `DoResend` | `startResendingEncryptedMessage`, `arqSend`, `arqDoResend` |
| thin-client reader | `Cancel`            | `cancelResendingEncryptedMessage`                      |
| timer              | `TimerFire`         | `enqueueResend`                                        |
| listener           | `Disconnect`, `Resume`, `Cleanup` | `onClosedConn`, `handleSessionToken`, `cleanupForAppID` |

The lock is held for each map access, not for a whole operation. The ingress
worker looks a reply up under the lock, releases it, and only then acts on the
message it found. The model represents that as two steps, `Lookup` and
`Handle`, with anything allowed in between.

Other elements that follow the code:

- **SURB ids.** An id is `<<message, generation>>`. Every rotation bumps the
  generation, which makes the previous id stale and replaces the keys that
  decrypt its reply (`rotateARQSurbIDLocked`).
- **Reply matching.** A reply matches only the current SURB id of a tracked
  operation. Anything else is discarded (`SurbIDReplyNoMatch`).
- **The state machine.** `Outcome` transcribes `computeARQStateTransition` and
  the payload outcomes of `handlePayloadReply`.
- **Only the egress worker rotates.** When a reply calls for another round,
  the handler sets the state and queues a resend (`scheduleARQFollowUp`). The
  follow-up then leaves on the scheduler's tick, and not in reaction to the
  reply. `arqDoResend` looks the operation up before it rotates.
- **The terminal branches do not check** that the operation is still tracked.
  The model has no such check either.
- **A timer that fires with no connection is armed again**, to try later.
- **Replies to the application.** The model counts every
  `StartResendingEncryptedMessageReply`, including the Cancelled reply that a
  cancel sends to the original call.

## Two switches

| Constant      | `TRUE` means                                           |
|---------------|--------------------------------------------------------|
| `Atomic`      | nothing runs between `Lookup` and `Handle`             |
| `Disconnects` | the thin client may disconnect and resume              |

With `Atomic = TRUE` and `Disconnects = FALSE` the model describes the
protocol alone. Turning a switch shows what that feature adds.

## Properties

| Invariant               | Statement                                                              |
|-------------------------|------------------------------------------------------------------------|
| `TypeOK`                | Type invariant.                                                        |
| `AtMostOneResponse`     | The application receives at most one reply per operation.              |
| `NoSilentDrop`          | An operation is never forgotten without a reply, while the session lives. |
| `NoOrphan`              | A tracked operation of a connected client can still make progress.     |
| `CancelIsFinal`         | A cancelled operation is never tracked again.                          |
| `NoStrayTimer`          | An operation that is not tracked has no armed timer.                   |
| `CompletionMatchesKind` | Only an idempotent write completes on an ACK. A read retries on BoxIDNotFound. |

Two further invariants are expected to fail and exist to produce a witness
trace: `NeverCompletes` and `NeverStale`.

## Results

| Config             | `Atomic` | `Disconnects` | Expected result              | Distinct states |
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

Every configuration has two operations and at most two rotations each. Each
file is named `ClientARQ_<Config>.cfg`. State counts are from TLC 2.19. TLC
stops at the first counterexample, so a failing configuration has no
meaningful count.

Which invariant holds where:

| Invariant               | `Sequential` | `Concurrent` | `Disconnect` |
|-------------------------|--------------|--------------|--------------|
| `AtMostOneResponse`     | holds        | violated     | holds        |
| `NoSilentDrop`          | holds        | violated     | violated     |
| `NoOrphan`              | holds        | holds        | violated     |
| `CancelIsFinal`         | holds        | holds        | holds        |
| `NoStrayTimer`          | holds        | violated     | holds        |
| `CompletionMatchesKind` | holds        | holds        | holds        |

## What the model shows

The protocol is sound. With atomic reply handling and a connected client,
every property holds.

The lookup before rotating does its job. `CancelIsFinal` holds with full
concurrency, and fails if the lookup is removed from the model.

The model finds three problems. Each trace is short.

### A cancel racing a reply produces two replies

`ClientARQ_RaceCancel.cfg`

1. The ingress worker looks up a reply and finds the operation.
2. The application cancels. The operation is removed, and the original call
   is answered with a Cancelled error.
3. The ingress worker handles the reply, reaches a terminal outcome, and
   answers the original call again.

The terminal branches of `handlePigeonholeARQReply` and `handlePayloadReply`
delete the map entries and call `finishARQMessage` without checking that the
operation is still tracked.

### A resend racing a reply loses the operation

`ClientARQ_RaceResend.cfg`

1. The retry timer fires and the resend is queued.
2. A late reply arrives. The ingress worker looks it up and finds the
   operation.
3. The egress worker re-sends, which rotates the operation to a fresh SURB
   and fresh keys.
4. The ingress worker decrypts the reply with the keys the operation holds
   now. They are the wrong keys. Decryption fails and `dropARQMessage`
   deletes the operation.

The application is never answered, and nothing retries. The timer of the new
SURB stays armed, which is what `ClientARQ_RaceTimer.cfg` shows. It is
harmless: when it fires, nothing is found.

### A disconnect within the grace period strands operations

`ClientARQ_DisconnectOrphan.cfg` and `ClientARQ_DisconnectDrop.cfg`

A session-aware client that disconnects keeps its state for a grace period
and may resume. While it is away:

- **A reply arrives.** `handleReply` cancels the timer, then
  `handlePigeonholeARQReply` finds no connection and returns. The operation
  stays tracked and is never re-sent.
- **A queued resend runs.** `arqDoResend` finds no connection and deletes the
  operation.

After the client resumes, the operation is stuck or gone, and the application
is still waiting.

A timer that fires while the client is away does no harm. `enqueueResend`
arms it again, and once the client is back the resend is queued. An earlier
version of the code dropped the timer there.

### Confirmation in the Go code

Three problems were replayed against the daemon code, by calling the real
functions in the order the model found.

| Problem                            | Model predicts                       | Go code does                        |
|------------------------------------|--------------------------------------|-------------------------------------|
| Cancel racing a reply              | two replies to one call              | Cancelled, then Success             |
| Resend racing a reply              | no reply, operation deleted          | no reply, both maps empty           |
| Reply arriving while disconnected  | tracked, no resend queued, no timer  | tracked, no resend queued, no timer |

Three more replays check behaviour that is not a problem.

| Behaviour                          | Model predicts                       | Go code does                        |
|------------------------------------|--------------------------------------|-------------------------------------|
| Nothing in between                 | one reply                            | one reply                           |
| Timer firing while disconnected    | timer armed again, resend queued after resume | the same                   |
| A read receives its ACK            | resend queued, SURB id unchanged     | the same                            |

The tests are in
[`arq_race_repro_test.go.txt`](arq_race_repro_test.go.txt), with instructions
at the top. Each passes when the code behaves as the model says. They show
what the code does for a given ordering. They do not show how often that
ordering occurs. The two races need a reply to arrive within a narrow window,
so they are likely to be rare.

The deletion in `arqDoResend` was read from the code and not replayed.

## What is not modelled

- **The courier and the network.** They are adversarial: any query sent so far
  may be answered, once, with any kind of reply, at any time or never.
- **The gateway connection.** A failed `SendPacket` is a lost query.
  "Connected" always means the thin client's connection to the daemon.
- **Unbounded retries.** Rotation is bounded by `MaxRetx`. At the bound a
  resend re-arms the timer without rotating, so the races are explored only
  below the bound.
- **Timing.** A timer may fire at any moment it is armed.
- **Copy commands.**
- **A full resend queue and a failed packet composition.** Both re-arm the
  timer in the code.
- **The flag `NoRetryOnBoxIDNotFound`.** A read always retries on
  BoxIDNotFound.
- **Liveness.** Only invariants are checked. `NoOrphan` is the closest
  substitute: it says progress is still possible, not that it happens.

## How the invariants were tested

Each invariant that is expected to hold was mutation-tested. An error was
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
| A read gives up on BoxIDNotFound                   | `CompletionMatchesKind`          |
| An idempotent write never completes on an ACK      | `WitnessCompletes` stops failing |

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
java -jar tla2tools.jar -config ClientARQ_RaceCancel.cfg ClientARQ.tla
```
