----------------------------- MODULE VotingAuthority -----------------------------
\* A TLA+ model of the Katzenpost voting directory-authority consensus
\* protocol (authority/voting/server/state.go).
\*
\* The real protocol drives each authority through a timed FSM within an epoch:
\*
\*   AcceptDescriptor -> AcceptVote -> AcceptReveal
\*                    -> AcceptCert  -> AcceptSignature
\*
\* with deadlines at 1/8, 2/8, 3/8, 4/8, 5/8 of the epoch. This model abstracts
\* that timed FSM into three message-exchange rounds that capture the
\* consensus-relevant behaviour:
\*
\*   "vote"  - every authority broadcasts a vote. A vote carries the authority's
\*           view of the submitted node descriptors AND its shared-random
\*           commitment (folded together here: an authority's vote content
\*           doubles as its commitment, so equivocation on either is modelled
\*           uniformly).
\*
\*   "cert"  - every authority broadcasts a certificate summarising the votes it
\*           received. An authority merges everything it learns directly and via
\*           certificates. If a single authority is seen reporting different
\*           vote/commit content to different peers, it is detected as
\*           equivocating and excluded from the tally and the shared-random set
\*           (mirrors verifyCommits() in state.go). Each authority then computes
\*           its consensus document by threshold-tallying the votes it knows.
\*
\*   "sig"   - every authority broadcasts a signature over the document it
\*           computed. An honest authority signs ONLY its own document. A
\*           consensus document is finalised at an authority iff it collects at
\*           least Threshold valid signatures over that exact document
\*           (cert.VerifyThreshold).
\*
\* Message delivery in every round is nondeterministic: each authority receives
\* messages from an arbitrary subset of authorities (always including itself).
\* This models packet loss, asynchrony and a Byzantine sender selectively
\* withholding messages.
\*
\* Threshold = floor(N/2) + 1 (strict majority), exactly as
\* st.threshold = len(st.verifiers)/2 + 1 in state.go.
\*
\* ABSTRACTIONS / OUT OF SCOPE (deliberate, to keep the model checkable):
\*   - Cryptography is treated symbolically: signatures are unforgeable and an
\*     honest authority's signature is bound to the exact document it computed.
\*   - The BLAKE2b shared-random value is abstracted to the set of participating
\*     (non-equivocating, known) authorities; honest authorities with the same
\*     participant set derive the same SRV.
\*   - The explicit reveal round is folded into the vote round: an authority
\*     participates in the SRV iff its vote/commit is known and consistent.
\*
\* EPOCH BOUNDARY EXTENSION:
\*   The model runs MaxEpoch consecutive epochs. Each epoch's consensus
\*   produces a shared-random value (SRV) that is mixed into the NEXT epoch's
\*   documents (state.go: srv = BLAKE2b(... || prior_srv); genesis epoch uses
\*   the all-zero prior). At the epoch boundary:
\*     - if a unique document reached Threshold signatures, every honest
\*       authority adopts its SRV as the next prior (lagging authorities catch
\*       up via the bootstrap fetch, modelled abstractly);
\*     - if no document reached Threshold, the chain stalls and the prior SRV
\*       is carried over unchanged (mirrors the failed-epoch bootstrap/retry);
\*     - if two documents both reached Threshold (only possible under a
\*       Byzantine Agreement violation), the SRV chain forks permanently.

EXTENDS Naturals, FiniteSets

CONSTANTS
    Auths,      \* set of authority identities
    Byzantine,  \* subset of Auths that may behave arbitrarily
    Nodes,      \* set of candidate mix-node descriptors that may be voted on
    MaxEpoch    \* number of consecutive epochs to model (>= 1)

ASSUME ByzantineSubset == Byzantine \subseteq Auths
ASSUME NodesFinite     == IsFiniteSet(Nodes)
ASSUME AuthsFinite     == IsFiniteSet(Auths)
ASSUME MaxEpochPos     == MaxEpoch \in (Nat \ {0})

Honest    == Auths \ Byzantine
N         == Cardinality(Auths)
Threshold == (N \div 2) + 1

\* A shared-random value carried across epochs.  Abstracted to the epoch it was
\* produced in and the set of authorities that contributed to it.  Epoch 0 is
\* the genesis (all-zero) value used by the first epoch.
SRVValue   == [epoch : 0..MaxEpoch, participants : SUBSET Auths]
GenesisSRV == [epoch |-> 0, participants |-> {}]

\* The universe of possible (valid) documents.  A document fixes the epoch, the
\* agreed node descriptors, the set of authorities contributing shared
\* randomness this epoch (srv), and the prior-epoch SRV it chains onto.  The
\* "valid" field lets the distinguished "no document" value below be a record
\* too, so all comparisons stay record-to-record (TLC refuses to compare a
\* string with a record).
Doc == [valid : {TRUE}, epoch : 1..MaxEpoch, desc : SUBSET Nodes,
        srv : SUBSET Auths, prior : SRVValue]

\* Distinguished "no document" value.
NoDoc == [valid |-> FALSE, epoch |-> 0, desc |-> {},
          srv |-> {}, prior |-> GenesisSRV]

\* The SRV value a finalised document contributes to the next epoch's chain.
SRVof(D) == [epoch |-> D.epoch, participants |-> D.srv]

VARIABLES
    epoch,      \* current epoch number in 1..MaxEpoch
    priorSRV,   \* [Auths -> SRVValue]   prior-epoch SRV each authority chains onto
    phase,      \* "vote" -> "cert" -> "sig" -> "done"
    descView,   \* [Auths -> SUBSET Nodes]   each authority's local view of descriptors
    voteMsg,    \* [Auths -> [Auths -> SUBSET Nodes]]  voteMsg[a][b] = content a sent to b
    recvVote,   \* [Auths -> SUBSET Auths]   whose votes each authority received
    recvCert,   \* [Auths -> SUBSET Auths]   whose certs each authority received
    recvSig,    \* [Auths -> SUBSET Auths]   whose signatures each authority received
    myDoc,      \* [Auths -> Doc \cup {NoDoc}]   document each authority computed
    sigSet,     \* [Auths -> SUBSET Doc]    documents each authority has signed
    finalDoc    \* [Auths -> Doc \cup {NoDoc}]   document each authority finalised

vars == <<epoch, priorSRV, phase, descView, voteMsg, recvVote, recvCert,
          recvSig, myDoc, sigSet, finalDoc>>

\* Knowledge derivation.
\*
\* ReportedContents(b, a, rv, rc) is the set of distinct vote/commit contents
\* that authority b has heard attributed to authority a, either directly
\* (a in rv[b]) or relayed in a certificate from some c in rc[b] that had heard
\* a directly.
\*
\*   |ReportedContents| = 0  -> b never learned a's vote (a not counted)
\*   |ReportedContents| = 1  -> b knows a's vote (a is a "known voter")
\*   |ReportedContents| > 1  -> a equivocated; b excludes a entirely
ReportedContents(b, a, rv, rc) ==
    (IF a \in rv[b] THEN {voteMsg[a][b]} ELSE {})
        \cup
    {voteMsg[a][c] : c \in {cc \in rc[b] : a \in rv[cc]}}

KnownVoters(b, rv, rc) ==
    {a \in Auths : Cardinality(ReportedContents(b, a, rv, rc)) = 1}

VoteOf(b, a, rv, rc) ==
    CHOOSE v \in ReportedContents(b, a, rv, rc) : TRUE

\* Descriptors with at least Threshold supporting votes among known voters.
DescTally(b, rv, rc) ==
    {n \in Nodes :
        Cardinality({a \in KnownVoters(b, rv, rc) : n \in VoteOf(b, a, rv, rc)})
            >= Threshold}

\* The document authority b computes from what it knows, chained onto b's
\* current prior-epoch SRV.
DocOf(b, rv, rc) ==
    [valid |-> TRUE,
     epoch |-> epoch,
     desc  |-> DescTally(b, rv, rc),
     srv   |-> KnownVoters(b, rv, rc),
     prior |-> priorSRV[b]]

\* Type invariant.
TypeOK ==
    /\ epoch \in 1..MaxEpoch
    /\ priorSRV \in [Auths -> SRVValue]
    /\ phase \in {"vote", "cert", "sig", "done"}
    /\ descView \in [Auths -> SUBSET Nodes]
    /\ voteMsg  \in [Auths -> [Auths -> SUBSET Nodes]]
    /\ recvVote \in [Auths -> SUBSET Auths]
    /\ recvCert \in [Auths -> SUBSET Auths]
    /\ recvSig  \in [Auths -> SUBSET Auths]
    /\ myDoc    \in [Auths -> Doc \cup {NoDoc}]
    /\ sigSet   \in [Auths -> SUBSET Doc]
    /\ finalDoc \in [Auths -> Doc \cup {NoDoc}]

\* Initial state.
\*
\* The first epoch starts from the genesis SRV.  Each authority has an arbitrary
\* local view of descriptors.  An honest authority sends the same vote (= its
\* view) to everyone; a Byzantine authority may send arbitrary, per-recipient
\* content (equivocation).
Init ==
    /\ epoch = 1
    /\ priorSRV = [a \in Auths |-> GenesisSRV]
    /\ phase = "vote"
    /\ descView \in [Auths -> SUBSET Nodes]
    /\ voteMsg \in [Auths -> [Auths -> SUBSET Nodes]]
    /\ \A h \in Honest : \A b \in Auths : voteMsg[h][b] = descView[h]
    /\ recvVote = [a \in Auths |-> {}]
    /\ recvCert = [a \in Auths |-> {}]
    /\ recvSig  = [a \in Auths |-> {}]
    /\ myDoc    = [a \in Auths |-> NoDoc]
    /\ sigSet   = [a \in Auths |-> {}]
    /\ finalDoc = [a \in Auths |-> NoDoc]

\* Round 1: deliver votes. Each authority receives votes from an arbitrary
\* subset of authorities (always including itself).
DeliverVote ==
    /\ phase = "vote"
    /\ \E rv \in [Auths -> SUBSET Auths] :
            /\ \A a \in Auths : a \in rv[a]
            /\ recvVote' = rv
    /\ phase' = "cert"
    /\ UNCHANGED <<epoch, priorSRV, descView, voteMsg, recvCert, recvSig,
                   myDoc, sigSet, finalDoc>>

\* Round 2: deliver certificates and compute documents. Each authority merges
\* the votes it knows (directly + via received certs), detects equivocators, and
\* tallies a consensus document.
DeliverCert ==
    /\ phase = "cert"
    /\ \E rc \in [Auths -> SUBSET Auths] :
            /\ \A a \in Auths : a \in rc[a]
            /\ recvCert' = rc
            /\ myDoc' = [a \in Auths |-> DocOf(a, recvVote, rc)]
    /\ phase' = "sig"
    /\ UNCHANGED <<epoch, priorSRV, descView, voteMsg, recvVote, recvSig,
                   sigSet, finalDoc>>

\* Round 3: deliver signatures and finalise.
\*
\* Honest authorities sign exactly the document they computed. Byzantine
\* authorities may sign any subset of the documents honest authorities are
\* trying to finalise (signing anything else cannot help reach a quorum over an
\* honest authority's document). An authority finalises its own document iff it
\* gathers at least Threshold signatures over it.
HonestDocs == {myDoc[h] : h \in Honest}

DeliverSig ==
    /\ phase = "sig"
    /\ \E rs \in [Auths -> SUBSET Auths],
          bc \in [Byzantine -> SUBSET HonestDocs] :
            /\ \A a \in Auths : a \in rs[a]
            /\ LET ss == [a \in Auths |->
                            IF a \in Byzantine THEN bc[a] ELSE {myDoc[a]}]
               IN /\ recvSig' = rs
                  /\ sigSet'  = ss
                  /\ finalDoc' =
                       [a \in Auths |->
                          IF Cardinality({q \in rs[a] : myDoc[a] \in ss[q]})
                                 >= Threshold
                          THEN myDoc[a]
                          ELSE NoDoc]
    /\ phase' = "done"
    /\ UNCHANGED <<epoch, priorSRV, descView, voteMsg, recvVote, recvCert, myDoc>>

\* Epoch boundary.
\*
\* The canonical consensus for this epoch is a document that gathered at least
\* Threshold signatures across all authorities.  Agreement guarantees there is
\* at most one such document when no Byzantine fault occurs.
EpochConsensus ==
    {D \in HonestDocs :
        Cardinality({q \in Auths : D \in sigSet[q]}) >= Threshold}

\* Advance to the next epoch, carrying the SRV chain forward:
\*   - unique consensus  -> every honest authority adopts its SRV (lagging
\*                          authorities catch up via bootstrap);
\*   - no consensus      -> the chain stalls (prior SRV carried unchanged);
\*   - forked consensus  -> each authority keeps the SRV of the document it
\*                          finalised, so the chain forks permanently.
EpochAdvance ==
    /\ phase = "done"
    /\ epoch < MaxEpoch
    /\ epoch' = epoch + 1
    /\ priorSRV' =
         CASE Cardinality(EpochConsensus) = 1 ->
                  [a \in Auths |-> SRVof(CHOOSE D \in EpochConsensus : TRUE)]
           [] Cardinality(EpochConsensus) = 0 ->
                  priorSRV
           [] OTHER ->
                  [a \in Auths |->
                      IF finalDoc[a] # NoDoc THEN SRVof(finalDoc[a])
                      ELSE priorSRV[a]]
    /\ phase' = "vote"
    /\ recvVote' = [a \in Auths |-> {}]
    /\ recvCert' = [a \in Auths |-> {}]
    /\ recvSig'  = [a \in Auths |-> {}]
    /\ myDoc'    = [a \in Auths |-> NoDoc]
    /\ sigSet'   = [a \in Auths |-> {}]
    /\ finalDoc' = [a \in Auths |-> NoDoc]
    /\ \E dv \in [Auths -> SUBSET Nodes],
          vm \in [Auths -> [Auths -> SUBSET Nodes]] :
            /\ \A h \in Honest : \A b \in Auths : vm[h][b] = dv[h]
            /\ descView' = dv
            /\ voteMsg'  = vm

\* Terminal: the last epoch has finished.
Done ==
    /\ phase = "done"
    /\ epoch = MaxEpoch
    /\ UNCHANGED vars

Next == DeliverVote \/ DeliverCert \/ DeliverSig \/ EpochAdvance \/ Done

Spec == Init /\ [][Next]_vars

\* Properties.

\* SAFETY (Agreement): no two honest authorities finalise different
\* consensus documents.  This is the headline correctness property.
Agreement ==
    \A a \in Honest : \A b \in Honest :
        (finalDoc[a] # NoDoc /\ finalDoc[b] # NoDoc)
            => (finalDoc[a] = finalDoc[b])

\* SAFETY (Validity): any document an honest authority finalises is a
\* document some honest authority actually computed (i.e. consensus is not
\* fabricated solely by Byzantine authorities).
Validity ==
    \A a \in Honest :
        finalDoc[a] # NoDoc => (\E h \in Honest : finalDoc[a] = myDoc[h])

\* SAFETY (Integrity): a finalised document carries at least Threshold
\* signatures over it from authorities the finaliser heard from.
Integrity ==
    \A a \in Honest :
        finalDoc[a] # NoDoc =>
            Cardinality({q \in recvSig[a] : finalDoc[a] \in sigSet[q]}) >= Threshold

\* SAFETY (ChainConsistency): the epoch-boundary safety property.  All honest
\* authorities agree on the prior-epoch SRV they chain the current epoch onto.
\* This holds whenever no epoch has suffered an Agreement violation, and is
\* violated the moment a Byzantine fork splits the SRV chain.
ChainConsistency ==
    \A a, b \in Honest : priorSRV[a] = priorSRV[b]

\* SAFETY (ChainGrounded): a finalised document always chains onto an SRV from
\* a strictly earlier epoch (or genesis), so the chain never references itself
\* or the future.
ChainGrounded ==
    \A a \in Honest :
        finalDoc[a] # NoDoc => finalDoc[a].prior.epoch < finalDoc[a].epoch

\* Sanity / reachability helper.  TLC reports a "violation" trace that is in
\* fact a *successful* run in which every honest authority finalised the same
\* document.  Run with -invariant ConsensusUnreachable to obtain such a trace.
AllHonestFinalisedSame ==
    /\ \A h \in Honest : finalDoc[h] # NoDoc
    /\ \A a, b \in Honest : finalDoc[a] = finalDoc[b]

ConsensusUnreachable == ~AllHonestFinalisedSame

=============================================================================
