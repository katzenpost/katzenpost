# Mix Node TLA+ Model

A formal model of a Katzenpost mix node's packet-processing pipeline, abstracted
from the `server` package. It captures the safety-critical mechanisms of a mix
node rather than its wire formats or cryptography.

## What is modelled

The model follows the lifecycle of a packet through a single mix node:

```
incoming conn -> inbound queue -> crypto worker -> scheduler queue -> outgoing dispatch
```

| Implementation concept                                   | Model element |
| -------------------------------------------------------- | ------------- |
| `inboundPackets` channel                                 | `AdmitExternal` moving a packet to `INBOUND` |
| Crypto worker Sphinx unwrap + mix-key selection          | `Unwrap` with the live key window `{E-1, E, E+1}` |
| Per-`MixKey` replay bloom filter (`IsReplay`/`TestAndSet`)| `replayCache` of `<<epoch, tag>>` pairs |
| Mix-key sliding window + `Prune` (forward secrecy)       | unwrap only succeeds when `epoch` is in window |
| `UnwrapDelay` dwell-time drop                            | `excessive_dwell` drop |
| Scheduler per-packet delay queue                         | `qdisp = now + delay`, `Dispatch` when `now >= qdisp` |
| `absoluteMaxDelay` drop                                  | `delay_exceeds_max` drop |
| `timerSlack` deadline drop                               | `deadline_blown` drop |
| Missing outgoing connection / invalid forward dest       | `no_connection` drop |
| Non-routable unwrap result                               | `unwrap_failed` drop |
| Local delivery (gateway `toUser` / SURB reply)           | `DELIVERED` state |
| Decoy / SURB loop traffic                                | `AdmitDecoy` entering the scheduler directly |
| Epoch rollover (key rotation)                            | `Tick` advancing `now`, epoch = `now \div EpochLen` |

Each packet ends in exactly one terminal state: `FORWARDED`, `DELIVERED`, or
`DROPPED` (with a concrete reason).

## Safety properties checked

| Invariant            | Meaning |
| -------------------- | ------- |
| `TypeOK`             | All variables stay within their declared domains. |
| `ReplayFreedom`      | No `<<epoch, tag>>` is accepted more than once: the per-key replay cache prevents duplicate processing. |
| `ForwardSecrecy`     | A packet is only ever unwrapped with a key inside the live window; keys older than `current - 1` are pruned and can no longer decrypt. |
| `NoEarlyDispatch`    | A forwarded packet is never dispatched before its scheduled mixing delay elapses. |
| `MixingDelayBounded` | A forwarded packet is dispatched within `SchedulerSlack` of its deadline (otherwise it is dropped). |
| `ForwardedValid`     | Only routable packets with a valid destination and acceptable delay are forwarded. |
| `DeliveredLocal`     | Locally delivered packets are exactly the `toUser` / `surb` kinds. |
| `DropAccounted`      | Every dropped packet carries a non-`none` reason; nothing is silently lost. |

## Configuration

`MixNode.cfg` models a healthy node:

| Constant         | Value      | Notes |
| ---------------- | ---------- | ----- |
| `Packets`        | `{p1, p2}` | two instances allow replays of a shared tag |
| `Tags`           | `{t1}`     | single tag so `p1`/`p2` can collide |
| `MaxTick`        | `3`        | bounded clock horizon |
| `EpochLen`       | `1`        | one tick per epoch (exercises rotation quickly) |
| `NumMixKeys`     | `2`        | `maxDelay = NumMixKeys * EpochLen = 2` |
| `UnwrapDelay`    | `2`        | dwell bound before an inbound packet is dropped |
| `SchedulerSlack` | `1`        | lateness tolerated at dispatch |

## Running

Requires Java. Download the TLA+ tools and run TLC:

```sh
curl -sSL -o tla2tools.jar \
  https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar

# Parse check
java -cp tla2tools.jar tla2sany.SANY MixNode.tla

# Model check
java -cp tla2tools.jar tlc2.TLC -config MixNode.cfg MixNode.tla

# Clean up (do not commit the jar or TLC output)
rm -rf tla2tools.jar states *.old MC*
```

The healthy configuration explores ~11M distinct states and satisfies all
invariants.

## Notes

- Time is bounded by `MaxTick`; a queued packet whose `qdisp` exceeds the
  horizon may remain `QUEUED` at the end. That is a property of the finite
  exploration bound, not a liveness bug. Raise `MaxTick` to drain such packets.
- The replay cache is modelled as monotonic. The real node prunes a key's cache
  when the key is pruned, but a pruned epoch can never re-enter the live window
  (epochs only increase), so no packet for that epoch could be accepted again;
  the monotonic abstraction is therefore equivalent for `ReplayFreedom`.
- The invariants are written as mechanism guarantees, so the healthy
  configuration passes. To study failures, disable a mechanism (e.g. drop the
  `isReplay` branch in `Unwrap`) and observe `ReplayFreedom` produce a
  counterexample trace.
