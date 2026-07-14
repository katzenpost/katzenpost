--------------------------- MODULE ClientARQ ---------------------------
\* TLA+ model of the Katzenpost client's ARQ reliability protocol.
\*
\* The client (the `client` package) sends messages into the mixnet reliably
\* using a stop-and-wait ARQ built on SURBs (single-use reply blocks) as
\* acknowledgments. This model abstracts the protocol implemented across
\* arq.go, daemon.go (arqDoResend / rotateARQSurbIDLocked / handleReply /
\* enqueueResend / cancelResendingEncryptedMessage) and pigeonhole.go
\* (handlePigeonholeARQReply / computeARQStateTransition).
\*
\* Modelled mechanisms:
\*   - the stop-and-wait FSM: WAIT_ACK -> ACK_RCVD -> (payload) terminal,
\*     with idempotent writes completing on the ACK alone
\*   - SURB rotation: every retransmission and every "send new SURB" uses a
\*     fresh SURB id, so a reply carrying an old SURB id no longer matches
\*   - retransmission: retry (forever in production; bounded here) whenever a
\*     reply is lost or late
\*   - reply matching: a SURB reply is applied only if its SURB id is the
\*     message's CURRENT id, else it is a no-match and dropped
\*   - cancellation and the cancel/ack race: a cancel removes the tracking
\*     entry so a later reply finds no match; a cancelled op never completes
\*   - connection loss: while disconnected the client cannot send or receive,
\*     but outstanding ARQ messages are NOT dropped -- they resume on reconnect
\*
\* SURB ids are modelled as <<message, generation>>: each retransmission or
\* rotation bumps a message's generation, which is exactly what makes the
\* previous SURB id stale. Because the protocol is stop-and-wait, at most one
\* query per message is outstanding, so a single pendingReply slot per message
\* faithfully represents the in-flight SURB reply.

EXTENDS Naturals

CONSTANTS Msgs,      \* finite set of ARQ message identities
          MaxRetx    \* bound on retransmissions / rotations per message

ASSUME MaxRetx \in Nat /\ MaxRetx >= 1

ReplyKinds == {"ACK", "PAYLOAD", "ERROR"}

\* Message flavour, chosen per message in Init:
\*   read           - always needs a payload reply after the ACK
\*   write_idem      - default write: the ACK alone completes it (idempotent)
\*   write_nonidem   - write that still needs a payload reply after the ACK
MKinds == {"read", "write_idem", "write_nonidem"}

\* Lifecycle status of a message.
Statuses == {"NEW", "INFLIGHT", "DONE_OK", "DONE_ERR", "CANCELLED"}
Terminal == {"DONE_OK", "DONE_ERR", "CANCELLED"}

\* Stop-and-wait protocol state (meaningful while INFLIGHT).
FSMStates == {"WAIT_ACK", "ACK_RCVD"}

\* Record-based "no reply" sentinel (a plain string sentinel cannot be
\* compared against a reply record by TLC).
NoReply == [some |-> FALSE, gen |-> 0, kind |-> "ACK"]

ReplyOrNone ==
  {NoReply} \cup [some : {TRUE}, gen : 0 .. MaxRetx, kind : ReplyKinds]

VARIABLES connected,     \* is the client connected to its gateway?
          status,        \* message -> lifecycle status
          fsm,           \* message -> stop-and-wait protocol state
          retx,          \* message -> current generation (# rotations)
          pendingReply,  \* message -> outstanding SURB reply (or NoReply)
          completions,   \* message -> ghost count of terminal completions
          mkind          \* message -> flavour (immutable)

vars == <<connected, status, fsm, retx, pendingReply, completions, mkind>>

TypeOK ==
  /\ connected \in BOOLEAN
  /\ status \in [Msgs -> Statuses]
  /\ fsm \in [Msgs -> FSMStates]
  /\ retx \in [Msgs -> 0 .. MaxRetx]
  /\ pendingReply \in [Msgs -> ReplyOrNone]
  /\ completions \in [Msgs -> 0 .. 2]
  /\ mkind \in [Msgs -> MKinds]

Init ==
  /\ connected = TRUE
  /\ status = [m \in Msgs |-> "NEW"]
  /\ fsm = [m \in Msgs |-> "WAIT_ACK"]
  /\ retx = [m \in Msgs |-> 0]
  /\ pendingReply = [m \in Msgs |-> NoReply]
  /\ completions = [m \in Msgs |-> 0]
  /\ mkind \in [Msgs -> MKinds]

\* Pure ARQ FSM, mirroring computeARQStateTransition in arq.go.
\* Result .act is one of:
\*   "ERROR"   -> terminal failure (DONE_ERR)
\*   "DONE"    -> terminal success (DONE_OK)
\*   "NEWSURB" -> rotate to a fresh SURB and keep polling; .ns is the new state
\*   "IGNORE"  -> already terminal, do nothing
Outcome(st, rk, mk) ==
  IF rk = "ERROR"
    THEN [act |-> "ERROR"]
  ELSE IF st = "WAIT_ACK"
    THEN IF rk = "ACK"
           THEN IF mk = "write_idem"
                  THEN [act |-> "DONE"]
                  ELSE [act |-> "NEWSURB", ns |-> "ACK_RCVD"]
           ELSE [act |-> "DONE"]                    \* PAYLOAD while waiting
  ELSE IF st = "ACK_RCVD"
    THEN IF rk = "PAYLOAD"
           THEN [act |-> "DONE"]
           ELSE [act |-> "NEWSURB", ns |-> "ACK_RCVD"] \* duplicate ACK: keep polling
  ELSE [act |-> "IGNORE"]

-----------------------------------------------------------------------------
\* Actions.

Connect ==
  /\ connected' = ~connected
  /\ UNCHANGED <<status, fsm, retx, pendingReply, completions, mkind>>

\* arqSend: the thin client asks to reliably send a message; it enters the
\* ARQ tracking maps and its first query goes out (generation 0).
StartSend(m) ==
  /\ connected
  /\ status[m] = "NEW"
  /\ status' = [status EXCEPT ![m] = "INFLIGHT"]
  /\ fsm' = [fsm EXCEPT ![m] = "WAIT_ACK"]
  /\ retx' = [retx EXCEPT ![m] = 0]
  /\ pendingReply' = [pendingReply EXCEPT ![m] = NoReply]
  /\ UNCHANGED <<connected, completions, mkind>>

\* The courier answers the current query with some reply. A faulty or
\* adversarial courier may send any reply kind; the client FSM must stay
\* safe regardless. The reply is tagged with the message's current
\* generation (the SURB id it was sent under).
CourierRespond(m) ==
  /\ connected
  /\ status[m] = "INFLIGHT"
  /\ pendingReply[m].some = FALSE
  /\ \E k \in ReplyKinds :
        pendingReply' = [pendingReply EXCEPT
                           ![m] = [some |-> TRUE, gen |-> retx[m], kind |-> k]]
  /\ UNCHANGED <<connected, status, fsm, retx, completions, mkind>>

\* A SURB reply is lost in the network. The message stays INFLIGHT and must
\* be retransmitted (enqueueResend never silently drops a live message).
LoseReply(m) ==
  /\ pendingReply[m].some = TRUE
  /\ pendingReply' = [pendingReply EXCEPT ![m] = NoReply]
  /\ UNCHANGED <<connected, status, fsm, retx, completions, mkind>>

\* arqDoResend: the retransmission timer fires. The message rotates to a
\* fresh SURB id (generation + 1) and re-sends; any earlier reply is now
\* stale. Bounded by MaxRetx here (unbounded in production).
Retransmit(m) ==
  /\ connected
  /\ status[m] = "INFLIGHT"
  /\ retx[m] < MaxRetx
  /\ retx' = [retx EXCEPT ![m] = retx[m] + 1]
  /\ pendingReply' = [pendingReply EXCEPT ![m] = NoReply]
  /\ UNCHANGED <<connected, status, fsm, completions, mkind>>

\* handleReply + handlePigeonholeARQReply: a pending SURB reply is delivered.
\* It is applied to the message only if the message is still INFLIGHT and the
\* reply's generation matches the current SURB id; otherwise it is a no-match
\* (SurbIDReplyNoMatch) and is dropped with no effect. This is where the
\* cancel/ack race is resolved: a cancel changes status away from INFLIGHT,
\* so a straggling reply can never resurrect a cancelled operation.
DeliverReply(m) ==
  /\ pendingReply[m].some = TRUE
  /\ LET r == pendingReply[m] IN
       IF status[m] = "INFLIGHT" /\ r.gen = retx[m]
         THEN LET o == Outcome(fsm[m], r.kind, mkind[m]) IN
                CASE o.act = "ERROR" ->
                       /\ status' = [status EXCEPT ![m] = "DONE_ERR"]
                       /\ completions' = [completions EXCEPT ![m] = @ + 1]
                       /\ pendingReply' = [pendingReply EXCEPT ![m] = NoReply]
                       /\ UNCHANGED <<fsm, retx>>
                  [] o.act = "DONE" ->
                       /\ status' = [status EXCEPT ![m] = "DONE_OK"]
                       /\ completions' = [completions EXCEPT ![m] = @ + 1]
                       /\ pendingReply' = [pendingReply EXCEPT ![m] = NoReply]
                       /\ UNCHANGED <<fsm, retx>>
                  [] o.act = "NEWSURB" ->
                       \* rotate to a fresh SURB id and keep polling
                       /\ fsm' = [fsm EXCEPT ![m] = o.ns]
                       /\ retx' = [retx EXCEPT
                                     ![m] = IF retx[m] < MaxRetx
                                              THEN retx[m] + 1 ELSE retx[m]]
                       /\ pendingReply' = [pendingReply EXCEPT ![m] = NoReply]
                       /\ UNCHANGED <<status, completions>>
                  [] OTHER ->
                       /\ pendingReply' = [pendingReply EXCEPT ![m] = NoReply]
                       /\ UNCHANGED <<status, fsm, retx, completions>>
         ELSE \* stale generation or not INFLIGHT: no match, drop
           /\ pendingReply' = [pendingReply EXCEPT ![m] = NoReply]
           /\ UNCHANGED <<status, fsm, retx, completions>>
  /\ UNCHANGED <<connected, mkind>>

\* cancelResendingEncryptedMessage: the app cancels an outstanding operation.
\* The tracking entry is removed (status leaves INFLIGHT) and the retry timer
\* is cancelled. Works whether the message has been sent yet or not, and while
\* disconnected. A cancel of an already-terminal message is a no-op success
\* (not modelled as a state change).
Cancel(m) ==
  /\ status[m] \in {"NEW", "INFLIGHT"}
  /\ status' = [status EXCEPT ![m] = "CANCELLED"]
  /\ pendingReply' = [pendingReply EXCEPT ![m] = NoReply]
  /\ UNCHANGED <<connected, fsm, retx, completions, mkind>>

\* Stutter once every message is terminal, so TLC does not flag a deadlock at
\* the end of a bounded run.
Terminating ==
  /\ \A m \in Msgs : status[m] \in Terminal
  /\ UNCHANGED vars

Next ==
  \/ Connect
  \/ \E m \in Msgs : StartSend(m) \/ CourierRespond(m) \/ LoseReply(m)
                     \/ Retransmit(m) \/ DeliverReply(m) \/ Cancel(m)
  \/ Terminating

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* Safety properties.

\* The client never reports an ARQ operation's terminal outcome more than
\* once: no double delivery / double ACK from the client's accounting. This
\* is the exactly-once guarantee under retransmission and SURB rotation.
AtMostOnce ==
  \A m \in Msgs : completions[m] <= 1

\* A completed operation (success or error) was reported exactly once. Taken
\* with AtMostOnce this is exactly-once completion for terminated operations.
CompletedReportedOnce ==
  \A m \in Msgs :
    status[m] \in {"DONE_OK", "DONE_ERR"} => completions[m] = 1

\* Cancel wins the cancel/ack race: a cancelled operation is never reported
\* as completed. Once cancelled it carries no completion.
CancelIsFinal ==
  \A m \in Msgs : status[m] = "CANCELLED" => completions[m] = 0

\* Retransmission / rotation is bounded (retries forever in production; here
\* the model bound is respected).
RetxBounded ==
  \A m \in Msgs : retx[m] <= MaxRetx

\* Only an INFLIGHT message ever carries a pending in-flight reply: terminal
\* messages hold no outstanding SURB, so no straggler can act on them.
NoPendingWhenTerminal ==
  \A m \in Msgs :
    status[m] \in Terminal => pendingReply[m].some = FALSE

\* An idempotent write is only ever completed after an ACK or payload, never
\* left half-open: if it is DONE_OK it was tracked and reported once.
DoneImpliesReported ==
  \A m \in Msgs :
    (status[m] = "DONE_OK" \/ status[m] = "DONE_ERR") => completions[m] >= 1

=============================================================================
