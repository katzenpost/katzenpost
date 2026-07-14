# Client ARQ TLA+ Model

A formal model of the Katzenpost client's ARQ (Automatic Repeat reQuest)
reliability protocol, abstracted from the `client` package. The client sends
messages into the mixnet reliably using a stop-and-wait ARQ built on SURBs
(single-use reply blocks) as acknowledgments; this is the client's defining
safety-critical behavior.

## What is modelled

The model follows each reliable send through its full lifecycle:

```
StartResendingEncryptedMessage -> in-flight (WAIT_ACK) -> ... -> terminal (ack / error / cancelled)
```

| Implementation concept                                                | Model element |
| --------------------------------------------------------------------- | ------------- |
| `computeARQStateTransition` FSM (arq.go)                              | `Outcome(st, rk, mk)` |
| `ARQStateWaitingForACK` / `ACKReceived`                              | `fsm` states `WAIT_ACK` / `ACK_RCVD` |
| idempotent write completes on ACK; read / non-idempotent need payload | `mkind` flavours `write_idem` / `read` / `write_nonidem` |
| `arqDoResend` + `rotateARQSurbIDLocked` (retry forever, fresh SURB)   | `Retransmit` bumping the message generation |
| SURB rotation invalidating the old SURB id                            | SURB id = `<<message, generation>>`; stale replies no longer match |
| `handleReply` / `handlePigeonholeARQReply` matching by SURB id        | `DeliverReply`, applied only when `gen = retx[m]` |
| `SurbIDReplyNoMatch` (GC'd / stale / misrouted reply)                 | the no-match branch of `DeliverReply` (drop, no effect) |
| network / SURB loss forcing a retransmit                              | `LoseReply` |
| `cancelResendingEncryptedMessage` + timer `Cancel`                    | `Cancel` moving the message to `CANCELLED` |
| the cancel/ack race (reply kept live across hand-off)                | `Cancel` leaves `INFLIGHT`, so a later `DeliverReply` no-matches |
| disconnect: `enqueueResend` / `arqDoResend` no-op but do NOT drop      | `connected`; sends/replies gated, in-flight messages retained |
| faulty / adversarial courier reply                                   | `CourierRespond` may emit any reply kind |

Because the protocol is stop-and-wait, at most one query per message is
outstanding, so a single `pendingReply` slot per message is a faithful
representation of the in-flight SURB reply.

## Safety properties checked

| Invariant               | Meaning |
| ----------------------- | ------- |
| `TypeOK`                | All variables stay within their declared domains. |
| `AtMostOnce`            | The client never reports an operation's terminal outcome more than once — exactly-once accounting under retransmission and SURB rotation. |
| `CompletedReportedOnce` | A completed (success or error) operation was reported exactly once. |
| `CancelIsFinal`         | Cancel wins the cancel/ack race: a cancelled operation is never later reported as completed. |
| `RetxBounded`           | Retransmission / rotation respects the model bound (unbounded in production). |
| `NoPendingWhenTerminal` | A terminal message holds no outstanding SURB, so no straggling reply can act on it. |
| `DoneImpliesReported`   | A message in a done state was tracked and reported at least once (no half-open completion). |

The key results: retransmission with SURB rotation never causes a double
completion, a reply carrying a stale SURB id is always a no-match, and a
cancel can never be undone by a racing acknowledgment.

## Configuration

`ClientARQ.cfg` models two concurrent operations with up to two rotations
each; the three message flavours are chosen nondeterministically in `Init`, so
all combinations are explored:

| Constant   | Value        | Notes |
| ---------- | ------------ | ----- |
| `Msgs`     | `{m1, m2}`   | two concurrent ARQ operations |
| `MaxRetx`  | `2`          | bound on retransmissions / SURB rotations per message |

## Running

Requires Java. Download the TLA+ tools and run TLC:

```sh
curl -sSL -o tla2tools.jar \
  https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar

# Parse check
java -cp tla2tools.jar tla2sany.SANY ClientARQ.tla

# Model check
java -cp tla2tools.jar tlc2.TLC -config ClientARQ.cfg ClientARQ.tla

# Clean up (do not commit the jar or TLC output)
rm -rf tla2tools.jar states *.old MC*
```

The configuration explores ~17.7k distinct states (depth 14) and satisfies all
invariants.

## Notes

- SURB ids are modelled as `<<message, generation>>`. Each retransmission or
  "send new SURB" bumps the generation, which is exactly what makes the prior
  SURB id stale — the mechanism behind `SurbIDReplyNoMatch` for late replies.
- Retransmission is bounded by `MaxRetx` for a finite state space; the real
  Pigeonhole ARQ retries forever (there is no `MaxRetransmissions` check in
  `arqDoResend`). A message that exhausts the bound simply waits for a
  non-lost reply in the model.
- `CourierRespond` may return any reply kind, modelling a faulty or
  adversarial courier. The invariants hold even so: the client FSM cannot be
  driven into a double completion or an un-cancelled state by unexpected
  replies.
- Not modelled: the Poisson send scheduling / decoy cover traffic
  (`sender.go`, `rates.go`) and the SURB GC timer wall-clock budget. Those are
  rate/timing concerns orthogonal to the ARQ correctness properties above.
