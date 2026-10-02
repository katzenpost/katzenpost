--------------------------- MODULE ClientARQ ---------------------------
\* A TLA+ model of the Katzenpost client daemon's ARQ: the stop-and-wait
\* protocol that sends a Pigeonhole query into the mixnet and retransmits it
\* until a reply arrives on a SURB (single-use reply block).
\*
\* It follows arq.go (computeARQStateTransition), daemon.go (handleReply,
\* enqueueResend, scheduleARQFollowUp, arqDoResend, rotateARQSurbIDLocked,
\* dropARQMessage, cleanupForAppID) and pigeonhole.go (arqSend,
\* handlePigeonholeARQReply, handlePayloadReply,
\* cancelResendingEncryptedMessage).
\*
\* WHO RUNS WHAT. The daemon touches an ARQ message from three goroutines,
\* which share the two ARQ maps under replyLock:
\*
\*   ingress worker      Lookup, Handle   a SURB reply arrives and is applied
\*   egress worker       Start, DoResend  queries are sent and re-sent
\*   thin-client reader  Cancel           the application cancels
\*
\* A timer goroutine runs TimerFire. The lock is held for each map access,
\* not for a whole operation. In particular the ingress worker looks a reply
\* up under the lock (Lookup), releases it, and only later acts on the
\* message it found (Handle). Anything may happen in between.
\*
\* The constant Atomic closes that gap: when TRUE, nothing runs between
\* Lookup and Handle. Comparing the two settings separates what the protocol
\* guarantees from what the locking guarantees.
\*
\* A SURB id is modelled as <<message, generation>>. Every rotation bumps the
\* generation of the message, which makes the previous id stale and replaces
\* the keys that decrypt its reply. Only the egress worker rotates. The
\* ingress worker asks for a follow-up by queueing a resend, so that the
\* follow-up leaves on the scheduler's tick and not in reaction to the reply.
\*
\* ABSTRACTIONS / OUT OF SCOPE:
\*   - The courier and the network are adversarial. Any query sent so far may
\*     be answered, once, with any kind of reply, at any time or never. Loss
\*     of a query or a reply is a reply that never arrives.
\*   - The daemon's own connection to its gateway is not modelled. A failed
\*     SendPacket is a lost query. "Connected" here always means the thin
\*     client's connection to the daemon.
\*   - Rotation is bounded by MaxRetx. The implementation retries forever.
\*     At the bound a resend re-arms the timer without rotating.
\*   - Copy commands, a full resend queue and a failed packet composition
\*     are not modelled.
\*   - NoRetryOnBoxIDNotFound and the BoxAlreadyExists-as-success path are not
\*     modelled, so the invariants hold for the default flags only.
\*   - Timing is not modelled: a timer may fire at any moment it is armed.

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Msgs,          \* ARQ operations
    MaxRetx,       \* bound on SURB rotations per operation
    Atomic,        \* TRUE: nothing runs between Lookup and Handle
    Disconnects    \* TRUE: the thin client may disconnect

ASSUME MaxRetx \in Nat \ {0}
ASSUME Atomic \in BOOLEAN /\ Disconnects \in BOOLEAN

Symmetry == Permutations(Msgs)

Gens == 0 .. MaxRetx

\* read          - needs a payload reply after the ACK
\* write_idem    - default write: the ACK alone completes it
\* write_nonidem - write that needs a payload reply after the ACK
MKinds == {"read", "write_idem", "write_nonidem"}

\* NOTFOUND is a payload reply that decrypts to BoxIDNotFound.
ReplyKinds == {"ACK", "PAYLOAD", "ERROR", "NOTFOUND"}

\* The state of one operation.
Op == [kind      : MKinds,     \* fixed
       started   : BOOLEAN,    \* the application started it
       tracked   : BOOLEAN,    \* it is in the ARQ maps
       cancelled : BOOLEAN,    \* the application cancelled it
       fsm       : {"WAIT_ACK", "ACK_RCVD"},    \* ARQMessage.State
       gen       : Gens,       \* generation of the current SURB id and keys
       timer     : BOOLEAN,    \* a retry timer is armed for the current id
       resendQ   : SUBSET Gens,    \* SURB ids waiting in resendCh
       answered  : SUBSET Gens,    \* queries whose reply has arrived
       responses : 0 .. 2,     \* replies sent to the application, capped at 2
       doneBy    : ReplyKinds \cup {"NONE", "CANCEL"}]    \* cause of the latest

NewOp(k) == [kind |-> k, started |-> FALSE, tracked |-> FALSE,
             cancelled |-> FALSE, fsm |-> "WAIT_ACK", gen |-> 0,
             timer |-> FALSE, resendQ |-> {}, answered |-> {},
             responses |-> 0, doneBy |-> "NONE"]

VARIABLES
    conn,       \* the thin client's session: "up", "away" (disconnected, state
                \* kept for the grace period) or "closed" (state destroyed)
    op,         \* [Msgs -> Op]
    handling    \* the ingress worker's job: {} or one reply it has looked up

vars == <<conn, op, handling>>

Jobs == [m : Msgs, g : Gens, k : ReplyKinds]

TypeOK ==
    /\ conn \in {"up", "away", "closed"}
    /\ op \in [Msgs -> Op]
    /\ handling \subseteq Jobs /\ Cardinality(handling) <= 1

Init ==
    /\ conn = "up"
    /\ op \in {[m \in Msgs |-> NewOp(k[m])] : k \in [Msgs -> MKinds]}
    /\ handling = {}

connected == conn = "up"

\* Every action but Handle is guarded by Free: with Atomic it may not run
\* while the ingress worker is between Lookup and Handle.
Free == Atomic => handling = {}

\* r after one more reply is sent to the application, caused by why.
Responded(r, why) ==
    [r EXCEPT !.responses = IF @ < 2 THEN @ + 1 ELSE @, !.doneBy = why]

\* r with a fresh SURB id and its timer armed (rotateARQSurbIDLocked and the
\* timer Push that follows it). Rotating enters r in both maps under the new
\* id. At the bound the generation cannot grow, so the queued copy of the old
\* id is removed instead; it would have been stale.
Rotated(r) ==
    [r EXCEPT !.tracked = TRUE,
              !.gen = IF @ < MaxRetx THEN @ + 1 ELSE @,
              !.timer = TRUE,
              !.resendQ = @ \ {MaxRetx}]

Untracked(r) == [r EXCEPT !.tracked = FALSE, !.timer = FALSE]

\* r after enqueueResend is called for its current SURB id. If r is no longer
\* tracked, nothing happens. With a live connection the id goes on the resend
\* queue. Without one the timer is armed again, to try later.
Enqueued(r) ==
    IF ~r.tracked THEN r
    ELSE IF connected THEN [r EXCEPT !.resendQ = @ \cup {r.gen}]
    ELSE [r EXCEPT !.timer = TRUE]

\* The pure FSM, computeARQStateTransition plus the payload outcomes of
\* handlePayloadReply. The result is "RESPOND" (a terminal reply goes to the
\* application) or the state in which to rotate and keep polling.
Outcome(st, k, mk) ==
    CASE k = "ERROR"    -> "RESPOND"
      [] k = "NOTFOUND" -> IF mk = "read" THEN "WAIT_ACK" ELSE "RESPOND"
      [] k = "PAYLOAD"  -> "RESPOND"
      [] k = "ACK"      -> IF st = "WAIT_ACK" /\ mk = "write_idem"
                           THEN "RESPOND" ELSE "ACK_RCVD"

-----------------------------------------------------------------------------
\* The application.

\* startResendingEncryptedMessage, arqSend.
Start(m) ==
    /\ Free /\ connected /\ ~op[m].started
    /\ op' = [op EXCEPT ![m].started = TRUE, ![m].tracked = TRUE,
                        ![m].timer = TRUE]
    /\ UNCHANGED <<conn, handling>>

\* cancelResendingEncryptedMessage. If the operation is still tracked it is
\* removed and the original call is answered with a Cancelled error. If not,
\* only the cancel call itself is answered.
Cancel(m) ==
    LET r == [Untracked(op[m]) EXCEPT !.cancelled = TRUE]
    IN  /\ Free /\ connected /\ op[m].started /\ ~op[m].cancelled
        /\ op' = [op EXCEPT ![m] = IF op[m].tracked
                                   THEN Responded(r, "CANCEL") ELSE r]
        /\ UNCHANGED <<conn, handling>>

-----------------------------------------------------------------------------
\* Retransmission.

\* The retry timer fires (enqueueResend).
TimerFire(m) ==
    /\ Free /\ op[m].timer
    /\ op' = [op EXCEPT ![m] = Enqueued([op[m] EXCEPT !.timer = FALSE])]
    /\ UNCHANGED <<conn, handling>>

\* The egress worker takes a SURB id from the resend queue (arqDoResend). An
\* id that is not in the map is stale, or belongs to an operation that was
\* cancelled, and the resend is abandoned. That lookup is what stops a
\* rotation from undoing a cancel. With no live connection the operation is
\* deleted. Otherwise it is rotated and re-sent.
DoResend(m, g) ==
    LET r == [op[m] EXCEPT !.resendQ = @ \ {g}]
    IN  /\ Free /\ g \in op[m].resendQ
        /\ op' = [op EXCEPT ![m] =
                    IF ~(r.tracked /\ g = r.gen) THEN r
                    ELSE IF ~connected THEN [r EXCEPT !.tracked = FALSE]
                    ELSE Rotated(r)]
        /\ UNCHANGED <<conn, handling>>

-----------------------------------------------------------------------------
\* Replies.

\* A reply to the query sent under generation g reaches the ingress worker
\* (handleReply). A SURB is single use, so each query is answered at most
\* once. The reply matches only if g is the message's current SURB id. A match
\* cancels the retry timer and leaves the maps untouched; the worker now
\* holds the message. No match: the reply is discarded (SurbIDReplyNoMatch).
Lookup(m, g, k) ==
    LET match == op[m].tracked /\ g = op[m].gen
    IN  /\ handling = {}
        /\ op[m].started /\ g <= op[m].gen /\ g \notin op[m].answered
        /\ op' = [op EXCEPT ![m].answered = @ \cup {g},
                            ![m].timer = IF match THEN FALSE ELSE @]
        /\ handling' = IF match THEN {[m |-> m, g |-> g, k |-> k]} ELSE {}
        /\ UNCHANGED conn

\* The ingress worker acts on the message it holds (handlePigeonholeARQReply).
\*   - No live connection: it returns at once.
\*   - The message was rotated since Lookup: its keys are no longer those of
\*     this reply, decryption fails, and dropARQMessage deletes the operation.
\*   - A terminal outcome deletes the operation and answers the application.
\*     The implementation does not check that it is still tracked.
\*   - Otherwise the state is set and a follow-up is asked for
\*     (scheduleARQFollowUp).
Handle ==
    \E j \in handling :
        LET r == op[j.m]
            o == Outcome(r.fsm, j.k, r.kind)
            gone == [r EXCEPT !.tracked = FALSE]
        IN  /\ handling' = {}
            /\ op' = [op EXCEPT ![j.m] =
                        IF ~connected THEN r
                        ELSE IF j.g # r.gen THEN gone
                        ELSE IF o = "RESPOND" THEN Responded(gone, j.k)
                        ELSE Enqueued([r EXCEPT !.fsm = o])]
            /\ UNCHANGED conn

-----------------------------------------------------------------------------
\* The thin client's connection.

\* The connection drops. A session-aware client keeps its state for a grace
\* period (onClosedConn).
Disconnect ==
    /\ Disconnects /\ Free /\ conn = "up"
    /\ conn' = "away"
    /\ UNCHANGED <<op, handling>>

\* The client reconnects within the grace period (handleSessionToken).
Resume ==
    /\ Free /\ conn = "away"
    /\ conn' = "up"
    /\ UNCHANGED <<op, handling>>

\* The grace period expires, or the client closed explicitly
\* (cleanupForAppID). Every operation is deleted and its timer cancelled.
Cleanup ==
    /\ Free /\ conn = "away"
    /\ conn' = "closed"
    /\ op' = [m \in Msgs |-> Untracked(op[m])]
    /\ UNCHANGED handling

-----------------------------------------------------------------------------

Next ==
    \/ Handle \/ Disconnect \/ Resume \/ Cleanup
    \/ \E m \in Msgs :
          \/ Start(m) \/ Cancel(m) \/ TimerFire(m)
          \/ \E g \in Gens :
                \/ DoResend(m, g)
                \/ \E k \in ReplyKinds : Lookup(m, g, k)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* Properties.

\* The application receives at most one reply per operation, counting the
\* Cancelled reply.
AtMostOneResponse == \A m \in Msgs : op[m].responses <= 1

\* An operation is never forgotten without a reply, while the session lives.
NoSilentDrop ==
    \A m \in Msgs :
        (op[m].started /\ ~op[m].tracked /\ conn # "closed")
            => op[m].responses >= 1

\* A tracked operation of a connected client can still make progress: its
\* timer is armed, its resend is queued, or the ingress worker holds it.
NoOrphan ==
    \A m \in Msgs :
        (op[m].tracked /\ connected) =>
            \/ op[m].timer
            \/ op[m].gen \in op[m].resendQ
            \/ \E j \in handling : j.m = m

\* Only an idempotent write completes on an ACK, and a read never completes
\* on BoxIDNotFound: it retries.
CompletionMatchesKind ==
    \A m \in Msgs :
        /\ op[m].doneBy = "ACK" => op[m].kind = "write_idem"
        /\ op[m].doneBy = "NOTFOUND" => op[m].kind # "read"

\* A cancelled operation is never tracked again.
CancelIsFinal == \A m \in Msgs : op[m].cancelled => ~op[m].tracked

\* An operation that is not tracked has no armed timer.
NoStrayTimer == \A m \in Msgs : op[m].timer => op[m].tracked

\* EXPECTED TO FAIL. Each is checked to obtain a witness trace, which shows
\* that the behaviour it names is reachable and the properties above are not
\* vacuous.

\* Violated by an operation that completes on an ACK with exactly one reply.
NeverCompletes ==
    \A m \in Msgs :
        ~(op[m].doneBy = "ACK" /\ op[m].responses = 1 /\ ~op[m].cancelled)

\* Violated by a reply that arrives under a stale SURB id.
NeverStale ==
    \A m \in Msgs :
        \A g \in op[m].answered : g = op[m].gen \/ ~op[m].tracked

=============================================================================
