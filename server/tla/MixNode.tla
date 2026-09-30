---------------------------- MODULE MixNode ----------------------------
\* A TLA+ model of the path a packet takes through a Katzenpost mix node.
\*
\*   incoming connection -> crypto worker -> scheduler -> outgoing connection
\*
\* It follows server/internal/incoming (onSendPacket),
\* server/internal/cryptoworker (worker, routePacket),
\* server/internal/scheduler (worker) and server/internal/outgoing
\* (DispatchPacket, IsValidForwardDest).
\*
\* The model covers what happens to a packet after it unwraps: how long it
\* waits, where it may go given the role of the node and where it came from,
\* and why it may be dropped. Keys and replays are in MixKeys.tla.
\*
\* Time is a counter of ticks. One tick stands for one millisecond, which is
\* the smallest delay the crypto worker hands to the scheduler.
\*
\* ABSTRACTIONS / OUT OF SCOPE:
\*   - Unwrapping is one choice per packet: it succeeds or it fails.
\*   - There is one next hop, whose connection may come and go.
\*   - The gateway and service backends, the decoy handler and the wire are
\*     where a packet leaves the model.
\*   - Decoy packets the node creates do not pass through here. The
\*     implementation hands them straight to the outgoing connection.
\*   - Not modelled: a forward packet that unwraps with a payload, the rate
\*     limit on clients, the size limit of the scheduler queue, the burst
\*     limit, and a delay limit taken from the PKI document.

EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    Packets,         \* packets
    MaxTick,         \* last tick to explore
    UnwrapDelay,     \* longest wait for a crypto worker (Debug.UnwrapDelay)
    SchedulerSlack,  \* lateness tolerated at dispatch (Debug.SchedulerSlack)
    MaxDelay         \* longest delay accepted (NumMixKeys * epochtime.Period)

ASSUME MaxTick \in Nat /\ UnwrapDelay \in Nat /\ SchedulerSlack \in Nat
ASSUME MaxDelay \in Nat \ {0}

Symmetry == Permutations(Packets)

Roles == {"mix", "gateway", "service"}

\* What a packet turns out to be once unwrapped.
\*   forward    - for another node
\*   to_user    - for a user or service of this node
\*   surb_decoy - a SURB reply to a decoy loop of this node
\*   surb_other - any other SURB reply
Cmds == {"forward", "to_user", "surb_decoy", "surb_other"}

\* Where a packet is. The last four are where it leaves the model.
Places == {"new", "inbound", "handoff", "queued",
           "sent", "backend", "decoy", "dropped"}

Reasons == {"none",
            "unwrap_dwell_exceeded", "unwrap_failed",
            "provider_forward_from_mix", "delay_impossible",
            "zero_delay_excessive_dwell", "mix_received_non_forward",
            "client_to_local_user", "scheduler_next_hop_invalid",
            "scheduler_deadline_blown", "dispatch_no_connection"}

Packet == [place      : Places,
           reason     : Reasons,
           fromClient : BOOLEAN,    \* it arrived from a client
           cmd        : Cmds,
           delay      : 0 .. (MaxDelay + 1),    \* delay the sender asked for
           recvAt     : 0 .. MaxTick,    \* when it arrived
           wait       : 0 .. (MaxDelay + 1),    \* delay given to the scheduler
           dispatchAt : 0 .. (MaxTick + MaxDelay + 1),    \* when it is due
           sentAt     : 0 .. MaxTick]    \* when it left

VARIABLES
    now,     \* the clock
    role,    \* the role of the node, fixed
    connUp,  \* there is a connection to the next hop
    pkt      \* [Packets -> Packet]

vars == <<now, role, connUp, pkt>>

TypeOK ==
    /\ now \in 0 .. MaxTick
    /\ role \in Roles
    /\ connUp \in BOOLEAN
    /\ pkt \in [Packets -> Packet]

Blank == [place |-> "new", reason |-> "none", fromClient |-> FALSE,
          cmd |-> "forward", delay |-> 0, recvAt |-> 0, wait |-> 0,
          dispatchAt |-> 0, sentAt |-> 0]

Init ==
    /\ now = 0
    /\ role \in Roles
    /\ connUp \in BOOLEAN
    /\ pkt = [p \in Packets |-> Blank]

At(r, place)    == [r EXCEPT !.place = place]
Dropped(r, why) == [r EXCEPT !.place = "dropped", !.reason = why]

\* onSendPacket: a provider must know whether a packet came from a client or
\* from a mix.
MustForward(r)   == r.fromClient
MustTerminate(r) == role = "service" /\ ~r.fromClient

-----------------------------------------------------------------------------

\* A packet arrives and is queued for the crypto workers (onSendPacket). Only
\* a gateway has clients.
Arrive(p) ==
    /\ pkt[p].place = "new"
    /\ \E c \in BOOLEAN, k \in Cmds, d \in 0 .. (MaxDelay + 1) :
          /\ c => role = "gateway"
          /\ pkt' = [pkt EXCEPT ![p] =
                        [Blank EXCEPT !.place = "inbound", !.fromClient = c,
                                      !.cmd = k, !.delay = d, !.recvAt = now]]
    /\ UNCHANGED <<now, role, connUp>>

\* The delay handed to the scheduler for a forward packet that waited dwell
\* for a crypto worker (routePacket). The wait is taken off the delay. A
\* packet is never handed over with less than one tick, so that some mixing
\* always happens.
Adjusted(delay, dwell) == IF delay > dwell THEN delay - dwell ELSE 1

\* A packet that asked for no delay at all and still had to wait is dropped.
ZeroDelayLate(delay, dwell) == delay = 0 /\ dwell >= 1

\* What routePacket does with an unwrapped packet r that waited dwell.
Routed(r, dwell) ==
    IF r.cmd = "forward" THEN
        IF MustTerminate(r) THEN Dropped(r, "provider_forward_from_mix")
        ELSE IF r.delay > MaxDelay THEN Dropped(r, "delay_impossible")
        ELSE IF ZeroDelayLate(r.delay, dwell)
             THEN Dropped(r, "zero_delay_excessive_dwell")
        ELSE [At(r, "handoff") EXCEPT !.wait = Adjusted(r.delay, dwell)]
    ELSE IF role = "mix" THEN
        IF r.cmd = "surb_decoy" THEN At(r, "decoy")
        ELSE Dropped(r, "mix_received_non_forward")
    ELSE IF MustForward(r) THEN Dropped(r, "client_to_local_user")
    ELSE IF r.cmd = "surb_decoy" THEN At(r, "decoy")
    ELSE At(r, "backend")

\* A crypto worker takes a packet (worker). A packet that waited too long is
\* dropped unseen. Otherwise it unwraps, or it does not.
Unwrap(p) ==
    LET r     == pkt[p]
        dwell == now - r.recvAt
    IN  /\ r.place = "inbound"
        /\ \E unwraps \in BOOLEAN :
              pkt' = [pkt EXCEPT ![p] =
                         IF dwell > UnwrapDelay
                             THEN Dropped(r, "unwrap_dwell_exceeded")
                         ELSE IF ~unwraps THEN Dropped(r, "unwrap_failed")
                         ELSE Routed(r, dwell)]
        /\ UNCHANGED <<now, role, connUp>>

\* The scheduler takes a packet from the crypto workers and queues it. It
\* also checks the delay against MaxDelay, which cannot fail here: the crypto
\* worker has applied the same bound.
Enqueue(p) ==
    LET r == pkt[p]
    IN  /\ r.place = "handoff"
        /\ pkt' = [pkt EXCEPT ![p] =
                      IF ~connUp THEN Dropped(r, "scheduler_next_hop_invalid")
                      ELSE [At(r, "queued") EXCEPT !.dispatchAt = now + r.wait]]
        /\ UNCHANGED <<now, role, connUp>>

\* The scheduler takes a packet that is due from its queue. It drops a packet
\* that is later than the slack allows. The outgoing side drops one that has
\* no connection (DispatchPacket).
Dispatch(p) ==
    LET r == pkt[p]
    IN  /\ r.place = "queued" /\ now >= r.dispatchAt
        /\ pkt' = [pkt EXCEPT ![p] =
                      IF now - r.dispatchAt > SchedulerSlack
                          THEN Dropped(r, "scheduler_deadline_blown")
                      ELSE IF ~connUp
                          THEN Dropped(r, "dispatch_no_connection")
                      ELSE [At(r, "sent") EXCEPT !.sentAt = now]]
        /\ UNCHANGED <<now, role, connUp>>

\* The connection to the next hop comes or goes.
Flap ==
    /\ connUp' = ~connUp
    /\ UNCHANGED <<now, role, pkt>>

Tick ==
    /\ now < MaxTick
    /\ now' = now + 1
    /\ UNCHANGED <<role, connUp, pkt>>

Next ==
    \/ Tick \/ Flap
    \/ \E p \in Packets : Arrive(p) \/ Unwrap(p) \/ Enqueue(p) \/ Dispatch(p)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* Properties.

Is(p, place) == pkt[p].place = place

\* A packet that is sent has spent at least the delay its sender asked for in
\* the node, and at least one tick.
MinimumMixing ==
    \A p \in Packets :
        Is(p, "sent") =>
            /\ pkt[p].sentAt - pkt[p].recvAt >= pkt[p].delay
            /\ pkt[p].sentAt > pkt[p].recvAt

\* A packet from a client goes into the mixnet or nowhere. It cannot reach a
\* local user or service without being mixed.
ClientPacketsAreMixed ==
    \A p \in Packets :
        pkt[p].fromClient => ~Is(p, "backend") /\ ~Is(p, "decoy")

\* A service node sends on nothing that a mix gave it. Traffic cannot loop
\* back into the mixnet from its last layer.
ServiceNodeTerminates ==
    \A p \in Packets : (role = "service" /\ Is(p, "sent")) => pkt[p].fromClient

\* A mix has no users. Nothing reaches a backend on a mix.
MixHasNoBackend ==
    \A p \in Packets : role = "mix" => ~Is(p, "backend")

\* Only a forward packet is sent on, and only a SURB reply to a decoy of this
\* node reaches the decoy handler.
PlaceMatchesCommand ==
    \A p \in Packets :
        /\ Is(p, "sent") => pkt[p].cmd = "forward"
        /\ Is(p, "decoy") => pkt[p].cmd = "surb_decoy"
        /\ Is(p, "backend") => pkt[p].cmd # "forward"

\* EXPECTED TO FAIL. Each is checked to obtain a witness trace.

\* Violated by a packet that is sent on.
NeverSent == \A p \in Packets : ~Is(p, "sent")

\* Violated by a packet that reaches a backend.
NeverDelivered == \A p \in Packets : ~Is(p, "backend")

\* Violated by a packet that is sent after the scheduler held it for less
\* than the delay its sender asked for. The wait for a crypto worker counts
\* towards the delay.
NeverShortened ==
    \A p \in Packets : Is(p, "sent") => pkt[p].wait >= pkt[p].delay

=============================================================================
