# TLA+ model of the client ARQ

A model of the stop-and-wait ARQ in the client daemon, which sends a Pigeonhole
query into the mixnet and retransmits it until a reply arrives on a SURB. It
follows [`arq.go`](../arq.go), [`daemon.go`](../daemon.go) and
[`pigeonhole.go`](../pigeonhole.go), as they are on `main` at commit `e17bffb95`.

## What is modelled

An application starts an operation; the daemon sends the query with a fresh SURB
and arms a retry timer; a reply either answers the application or causes another
send with another fresh SURB; a timer that fires first causes a resend. The
application may cancel at any time and may lose its connection to the daemon.

Three goroutines and a timer touch an operation, sharing the two ARQ maps under
`replyLock`:

| Actor | Model actions | Code |
|---|---|---|
| ingress worker | `Lookup`, `Handle` | `handleReply`, `handlePigeonholeARQReply`, `handlePayloadReply`, `scheduleARQFollowUp` |
| egress worker | `Start`, `DoResend` | `startResendingEncryptedMessage`, `arqSend`, `arqDoResend` |
| thin-client reader | `Cancel` | `cancelResendingEncryptedMessage` |
| timer | `TimerFire` | `enqueueResend` |
| listener | `Disconnect`, `Resume`, `Cleanup` | `onClosedConn`, `handleSessionToken`, `cleanupForAppID` |

The lock is held per map access, not for a whole operation: the ingress worker
looks a reply up, releases the lock, and only then acts on what it found. That is
why `Lookup` and `Handle` are two steps with anything allowed in between, which
is what `Atomic = FALSE` explores.

Other elements follow the code. A SURB id is `<<message, generation>>` and every
rotation bumps the generation, making the previous id stale and replacing the
keys that decrypt its reply (`rotateARQSurbIDLocked`). A reply matches only the
current id of a tracked operation (`SurbIDReplyNoMatch`). `Outcome` transcribes
`computeARQStateTransition` and the payload outcomes of `handlePayloadReply`.
Only the egress worker rotates: a handler that wants another round sets the state
and queues a resend (`scheduleARQFollowUp`), which leaves on the scheduler's tick
rather than in reaction to the reply, and `arqDoResend` looks the operation up
before rotating. The terminal branches do not check that the operation is still
tracked, and the model has no such check either. A timer that fires with no
connection is armed again. Every `StartResendingEncryptedMessageReply` is
counted, including the Cancelled reply a cancel sends to the original call.

Two constants select what is explored: `Atomic`, nothing runs between `Lookup`
and `Handle`, and `Disconnects`, the thin client may disconnect and resume. Both
at their quiet setting describes the protocol alone.

## Properties

| Invariant | Statement |
|---|---|
| `TypeOK` | Type invariant. |
| `AtMostOneResponse` | The application receives at most one reply per operation. |
| `NoSilentDrop` | An operation is never forgotten without a reply, while the session lives. |
| `NoOrphan` | A tracked operation of a connected client can still make progress. |
| `CancelIsFinal` | A cancelled operation is never tracked again. |
| `NoStrayTimer` | An operation that is not tracked has no armed timer. |
| `CompletionMatchesKind` | Only an idempotent write completes on an ACK; a read retries on BoxIDNotFound. |

`NeverCompletes` and `NeverStale` are expected to fail and exist to produce a
witness trace. Each invariant expected to hold was mutation-tested, by
introducing a deliberate error into a copy of the specification and confirming
TLC reported it violated.

## Results

| Config | `Atomic` | `Disconnects` | Expected | Distinct states |
|---|---|---|---|---|
| `Sequential` | yes | no | all seven hold | 282,263 |
| `Concurrent` | no | no | five hold | 923,723 |
| `Disconnect` | yes | yes | seven hold | 406,649 |
| `RaceCancel` | no | no | `AtMostOneResponse` violated | |
| `RaceTimer` | no | no | `NoStrayTimer` violated | |
| `WitnessCompletes` | yes | no | `NeverCompletes` violated | |
| `WitnessStale` | yes | no | `NeverStale` violated | |

Every configuration has two operations and at most two rotations each. Each file
is `ClientARQ_<Config>.cfg` and says in its own comment what its result shows.
Counts are from TLC 2.19, the release `make tla` pins. A failing configuration
has no stable count, because TLC stops at the first counterexample its workers
reach and which one that is varies between runs of an unchanged tree.

Which invariant holds where:

| Invariant | `Sequential` | `Concurrent` | `Disconnect` |
|---|---|---|---|
| `AtMostOneResponse` | holds | violated | holds |
| `NoSilentDrop` | holds | holds | holds |
| `NoOrphan` | holds | holds | holds |
| `CancelIsFinal` | holds | holds | holds |
| `NoStrayTimer` | holds | violated | holds |
| `CompletionMatchesKind` | holds | holds | holds |

## What the model shows

The protocol is sound: with atomic reply handling and a connected client, every
property holds. The lookup before rotating does its job, and `CancelIsFinal`
fails if the lookup is removed from the model.

Three problems appeared once those assumptions were dropped. Two are fixed and
the model follows the fixed code, so their configurations fold into `Concurrent`
and `Disconnect`, which now carry the invariants that used to be the
counterexample. The third stands.

**A cancel racing a reply answers the application twice** (`RaceCancel`, still
open). The
ingress worker finds the operation, the application cancels and is answered with
a Cancelled error, and the worker then reaches a terminal outcome and answers
again. The terminal branches of `handlePigeonholeARQReply` and
`handlePayloadReply` delete the map entries and call `finishARQMessage` without
checking that the operation is still tracked.

**A resend racing a reply lost the operation** (`Concurrent`, fixed). The timer
fires and queues a resend; a late reply is looked up and found; the egress worker
rotates to a fresh SURB and fresh keys; the worker then decrypts with the keys
the operation holds now, which are the wrong ones. That deleted the operation,
leaving the application unanswered with nothing retrying; it now arms the timer
again. The timer of the new SURB stays armed, which is `RaceTimer`, and is
harmless because nothing is found when it fires.

**A disconnect within the grace period stranded operations**
(`Disconnect`, fixed). `resendCh` belongs to the connection, so a SURB id
still queued when the connection went away went with it and no timer was left
behind; and while a session-aware client was away a reply made `handleReply`
cancel the timer and `handlePigeonholeARQReply` return with no connection. Either
way the operation was still tracked after the client resumed, never re-sent, and
the application still waiting. `onClosedConn` now drains the queue back onto the
timer, and a reply inside the grace period is handled and queued for the client's
return.

All three were replayed against the daemon code by calling the real functions in
the order the model found, together with three replays of behaviour that is not a
problem. Each now asserts the behaviour the code gives, so the file is a
regression test for the orderings the model turned up. The tests are in
[`arq_race_repro_test.go.txt`](arq_race_repro_test.go.txt) with instructions at
the top. They show what the code does for a given ordering, not how often that
ordering occurs, and both races need a reply inside a narrow window, so they are
likely rare. The re-arm in `arqDoResend` when the connection has gone was read
from the code and not replayed; it needs a resend to be taken from the queue
after the connection has gone, which the scheduler makes a narrow window.

## What is not modelled

- **The courier and the network**, which are adversarial: any query sent so far
  may be answered, once, with any kind of reply, at any time or never.
- **The gateway connection.** A failed `SendPacket` is a lost query, and
  "connected" always means the thin client to the daemon.
- **Unbounded retries.** Rotation is bounded by `MaxRetx`, and at the bound a
  resend re-arms the timer without rotating, so the races are explored only below
  it.
- **`NoRetryOnBoxIDNotFound` and the `BoxAlreadyExists`-as-success path**, so
  the invariants hold for the default flags only.
- **Timing**, a timer firing at any moment it is armed.
- **Copy commands**, a full resend queue and a failed packet composition, the
  last two of which re-arm the timer in the code.
- **`NoRetryOnBoxIDNotFound`.** A read always retries.
- **The order of messages a resuming client receives.** `handleSessionToken`
  sends the session-token reply ahead of any resumed reply and replays the
  broadcasts skipped while the handshake gate was shut. A resume here is one step
  that makes the client connected, and replies are counted without ordering.
- **Liveness.** Only invariants are checked; `NoOrphan` says progress is still
  possible, not that it happens.

## Running

`make tla` from the repository root fetches the pinned tla2tools through
`make tla-tools`, which checks its digest, and runs every configuration of every model through
[`.ci/tla.sh`](../../.ci/tla.sh), comparing each verdict with the expected one
and exiting non-zero if any differs.

For one configuration and its trace, with the jar here or named by `TLA2TOOLS`:

```sh
java -jar tla2tools.jar -config ClientARQ_RaceCancel.cfg ClientARQ.tla
```
