---------------------------- MODULE MixNode ----------------------------
\* TLA+ model of a Katzenpost mix node packet-processing pipeline.
\*
\* This abstracts the behavior implemented in the `server` package:
\*   incoming conn  -> inboundPackets channel -> crypto worker (Sphinx unwrap,
\*   mix-key selection, replay check) -> scheduler (per-packet delay queue) ->
\*   outgoing conn dispatch.
\*
\* The model captures the safety-critical mechanisms rather than wire formats:
\*   - mix-key sliding window + pruning (forward secrecy)
\*   - per-key replay detection (the bloom filter / TestAndSet)
\*   - mixing-delay enforcement and deadline / max-delay drops
\*   - the set of drop reasons that retire a packet
\*   - locally generated decoy traffic entering the same scheduler
\*
\* Time is modelled as a discrete tick counter `now`; the current epoch is
\* `now \div EpochLen`. The crypto worker can only unwrap a packet whose key
\* epoch lies in the live window {E-1, E, E+1} (mirroring doUnwrap trying the
\* current, previous and next epoch keys); keys outside that window are pruned,
\* which is exactly the forward-secrecy guarantee.

EXTENDS Integers, FiniteSets

CONSTANTS Packets,        \* finite set of packet instance identities
          Tags,           \* finite set of Sphinx replay tags
          MaxTick,        \* bound on the logical clock
          EpochLen,       \* number of ticks per epoch
          NumMixKeys,     \* keys kept around (constants.NumMixKeys = 3)
          UnwrapDelay,    \* max dwell time in the inbound queue before drop
          SchedulerSlack  \* max lateness tolerated at dispatch

ASSUME EpochLen >= 1 /\ NumMixKeys >= 1 /\ MaxTick >= 0

\* The kinds of packet a crypto worker can produce from a successful unwrap,
\* plus locally generated decoy traffic.
Kinds == {"forward", "toUser", "surb", "nonroutable", "decoy"}

\* Largest mixing delay the scheduler will accept (absoluteMaxDelay).
maxDelay == NumMixKeys * EpochLen

\* Epoch that contains tick t.
Epoch(t) == t \div EpochLen

\* Domain of packet key-epochs explored (includes one future epoch).
EpochDomain == 0 .. (MaxTick \div EpochLen + 1)

\* Immutable per-packet content.
ContentRec == [epoch  : EpochDomain,
               tag    : Tags,
               delay  : 0 .. (maxDelay + 1),
               kind   : Kinds,
               destOK : BOOLEAN]

Terminal == {"FORWARDED", "DELIVERED", "DROPPED"}

VARIABLES now,          \* logical clock tick
          pstate,       \* packet -> lifecycle state
          arr,          \* packet -> arrival tick (set on admission)
          qdisp,        \* packet -> scheduled dispatch tick (set when QUEUED)
          dtime,        \* packet -> actual dispatch tick (set when FORWARDED)
          reason,       \* packet -> drop reason ("none" if not dropped)
          accepted,     \* packet -> TRUE once cryptographically unwrapped
          uepoch,       \* packet -> epoch at which it was unwrapped (ghost)
          replayCache,  \* set of <<epoch, tag>> pairs already accepted
          content       \* packet -> ContentRec (immutable)

vars == <<now, pstate, arr, qdisp, dtime, reason, accepted, uepoch,
          replayCache, content>>

Reasons == {"none", "unwrap_no_key", "unwrap_failed", "replay",
            "excessive_dwell", "delay_exceeds_max", "no_connection",
            "deadline_blown"}

States == {"NEW", "INBOUND", "QUEUED"} \cup Terminal

TypeOK ==
  /\ now \in 0 .. MaxTick
  /\ pstate \in [Packets -> States]
  /\ arr \in [Packets -> 0 .. MaxTick]
  /\ qdisp \in [Packets -> 0 .. (MaxTick + maxDelay + 1)]
  /\ dtime \in [Packets -> 0 .. MaxTick]
  /\ reason \in [Packets -> Reasons]
  /\ accepted \in [Packets -> BOOLEAN]
  /\ uepoch \in [Packets -> EpochDomain]
  /\ replayCache \subseteq (EpochDomain \X Tags)
  /\ content \in [Packets -> ContentRec]

Init ==
  /\ now = 0
  /\ content \in [Packets -> ContentRec]
  /\ pstate = [p \in Packets |-> "NEW"]
  /\ arr = [p \in Packets |-> 0]
  /\ qdisp = [p \in Packets |-> 0]
  /\ dtime = [p \in Packets |-> 0]
  /\ reason = [p \in Packets |-> "none"]
  /\ accepted = [p \in Packets |-> FALSE]
  /\ uepoch = [p \in Packets |-> 0]
  /\ replayCache = {}

\* An external packet arrives off the wire and is queued for the crypto worker.
AdmitExternal(p) ==
  /\ pstate[p] = "NEW"
  /\ content[p].kind # "decoy"
  /\ pstate' = [pstate EXCEPT ![p] = "INBOUND"]
  /\ arr' = [arr EXCEPT ![p] = now]
  /\ UNCHANGED <<now, qdisp, dtime, reason, accepted, uepoch, replayCache,
                 content>>

\* A locally generated decoy (SURB loop) enters the scheduler directly: it is
\* not unwrapped and not subject to replay detection.
AdmitDecoy(p) ==
  /\ pstate[p] = "NEW"
  /\ content[p].kind = "decoy"
  /\ LET c == content[p]
         res == IF c.delay > maxDelay
                  THEN [st |-> "DROPPED", rs |-> "delay_exceeds_max"]
                ELSE IF ~c.destOK
                  THEN [st |-> "DROPPED", rs |-> "no_connection"]
                ELSE [st |-> "QUEUED", rs |-> "none"]
     IN /\ pstate' = [pstate EXCEPT ![p] = res.st]
        /\ reason' = [reason EXCEPT ![p] = res.rs]
        /\ qdisp' = IF res.st = "QUEUED"
                      THEN [qdisp EXCEPT ![p] = now + c.delay]
                      ELSE qdisp
        /\ arr' = [arr EXCEPT ![p] = now]
  /\ UNCHANGED <<now, dtime, accepted, uepoch, replayCache, content>>

\* The crypto worker dequeues an inbound packet and tries to unwrap it.
\* Precedence of outcomes mirrors the implementation:
\*   1. excessive dwell time -> drop
\*   2. no live key for the packet's epoch -> drop (forward secrecy)
\*   3. replayed tag under that key -> drop
\*   4. successful unwrap -> record tag, then route (deliver / forward / drop)
Unwrap(p) ==
  /\ pstate[p] = "INBOUND"
  /\ LET c        == content[p]
         e        == Epoch(now)
         dwell    == now - arr[p]
         isStale  == c.epoch \notin {e - 1, e, e + 1}
         isReplay == <<c.epoch, c.tag>> \in replayCache
         res ==
           IF dwell > UnwrapDelay
             THEN [st |-> "DROPPED", rs |-> "excessive_dwell", acc |-> FALSE]
           ELSE IF isStale
             THEN [st |-> "DROPPED", rs |-> "unwrap_no_key", acc |-> FALSE]
           ELSE IF isReplay
             THEN [st |-> "DROPPED", rs |-> "replay", acc |-> FALSE]
           ELSE IF c.kind = "nonroutable"
             THEN [st |-> "DROPPED", rs |-> "unwrap_failed", acc |-> TRUE]
           ELSE IF c.kind \in {"toUser", "surb"}
             THEN [st |-> "DELIVERED", rs |-> "none", acc |-> TRUE]
           ELSE IF c.delay > maxDelay
             THEN [st |-> "DROPPED", rs |-> "delay_exceeds_max", acc |-> TRUE]
           ELSE IF ~c.destOK
             THEN [st |-> "DROPPED", rs |-> "no_connection", acc |-> TRUE]
           ELSE [st |-> "QUEUED", rs |-> "none", acc |-> TRUE]
     IN /\ pstate' = [pstate EXCEPT ![p] = res.st]
        /\ reason' = [reason EXCEPT ![p] = res.rs]
        /\ accepted' = [accepted EXCEPT ![p] = res.acc]
        /\ uepoch' = IF res.acc THEN [uepoch EXCEPT ![p] = e] ELSE uepoch
        /\ replayCache' = IF res.acc
                            THEN replayCache \cup {<<c.epoch, c.tag>>}
                            ELSE replayCache
        /\ qdisp' = IF res.st = "QUEUED"
                      THEN [qdisp EXCEPT ![p] = now + c.delay]
                      ELSE qdisp
  /\ UNCHANGED <<now, arr, dtime, content>>

\* The scheduler dispatches a queued packet once its delay has elapsed.
\* A packet whose deadline was blown by more than SchedulerSlack is dropped.
Dispatch(p) ==
  /\ pstate[p] = "QUEUED"
  /\ now >= qdisp[p]
  /\ IF now - qdisp[p] > SchedulerSlack
       THEN /\ pstate' = [pstate EXCEPT ![p] = "DROPPED"]
            /\ reason' = [reason EXCEPT ![p] = "deadline_blown"]
            /\ UNCHANGED dtime
       ELSE /\ pstate' = [pstate EXCEPT ![p] = "FORWARDED"]
            /\ reason' = [reason EXCEPT ![p] = "none"]
            /\ dtime' = [dtime EXCEPT ![p] = now]
  /\ UNCHANGED <<now, arr, qdisp, accepted, uepoch, replayCache, content>>

\* Time advances; the epoch (and thus the live key window) may roll over.
Tick ==
  /\ now < MaxTick
  /\ now' = now + 1
  /\ UNCHANGED <<pstate, arr, qdisp, dtime, reason, accepted, uepoch,
                 replayCache, content>>

\* Stutter once the clock is exhausted so TLC does not report a deadlock on
\* packets that cannot make further progress within the bounded horizon.
Terminating ==
  /\ now = MaxTick
  /\ UNCHANGED vars

Next ==
  \/ \E p \in Packets : AdmitExternal(p) \/ AdmitDecoy(p)
                        \/ Unwrap(p) \/ Dispatch(p)
  \/ Tick
  \/ Terminating

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* Safety properties.

\* No replay tag is accepted more than once under the same key epoch. This is
\* the formal statement of the per-key replay cache guarantee.
ReplayFreedom ==
  \A p, q \in Packets :
    (p # q /\ accepted[p] /\ accepted[q]
       /\ content[p].epoch = content[q].epoch
       /\ content[p].tag = content[q].tag)
    => FALSE

\* A packet is only ever unwrapped with a key inside the live window, so a key
\* for an epoch older than (current - 1) has been pruned and can no longer
\* decrypt anything: forward secrecy.
ForwardSecrecy ==
  \A p \in Packets :
    accepted[p] =>
      content[p].epoch \in {uepoch[p] - 1, uepoch[p], uepoch[p] + 1}

\* A forwarded packet was never dispatched before its scheduled mixing delay.
NoEarlyDispatch ==
  \A p \in Packets :
    pstate[p] = "FORWARDED" => dtime[p] >= qdisp[p]

\* A forwarded packet was dispatched within the scheduler's slack of its
\* deadline (otherwise it would have been dropped as deadline_blown).
MixingDelayBounded ==
  \A p \in Packets :
    pstate[p] = "FORWARDED" => dtime[p] <= qdisp[p] + SchedulerSlack

\* Only routable packets with a valid destination and an acceptable delay are
\* ever forwarded.
ForwardedValid ==
  \A p \in Packets :
    pstate[p] = "FORWARDED" =>
      /\ content[p].kind \in {"forward", "decoy"}
      /\ content[p].destOK
      /\ content[p].delay <= maxDelay

\* Locally delivered packets are exactly the user / SURB-reply kinds.
DeliveredLocal ==
  \A p \in Packets :
    pstate[p] = "DELIVERED" => content[p].kind \in {"toUser", "surb"}

\* Every dropped packet carries a concrete, non-"none" reason; non-dropped
\* packets carry no drop reason. No packet is silently lost.
DropAccounted ==
  \A p \in Packets :
    /\ (pstate[p] = "DROPPED") <=> (reason[p] # "none")
    /\ pstate[p] \in States

=============================================================================
