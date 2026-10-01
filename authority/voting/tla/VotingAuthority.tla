----------------------------- MODULE VotingAuthority -----------------------------
\* A TLA+ model of the Katzenpost voting directory-authority consensus
\* protocol (authority/voting/server/state.go).
\*
\* The timed FSM of state.go (AcceptDescriptor -> AcceptVote -> AcceptReveal ->
\* AcceptCert -> AcceptSignature) is abstracted into three rounds and an epoch
\* boundary:
\*
\*   "vote"   - every authority broadcasts a vote: its descriptor view and its
\*              shared-random commitment.
\*   "cert"   - every authority holding Threshold votes broadcasts a
\*              certificate relaying the commitments it received. Each
\*              authority then computes its document.
\*   "sig"    - every authority signs the document it computed, and finalises
\*              it iff it collects Threshold signatures over that exact
\*              document.
\*   boundary - every authority picks the shared-random value (SRV) that the
\*              next epoch chains onto.
\*
\* Delivery in every round is lossy: each authority receives messages from an
\* arbitrary subset of authorities. This covers packet loss and a Byzantine
\* sender withholding messages. It does NOT cover asynchrony: the rounds are
\* atomic, so every authority is always in the same phase of the same epoch.
\*
\* ABSTRACTIONS / OUT OF SCOPE:
\*   - Cryptography is symbolic: signatures are unforgeable and an honest
\*     authority's signature is bound to the exact document it computed.
\*   - One value stands for both a vote's descriptor set and its commitment, so
\*     a Byzantine authority that sends two different values equivocates on
\*     both at once. In state.go it could vary its descriptors under a single
\*     commitment and stay a shared-random participant everywhere. That
\*     behaviour is not explored.
\*   - The reveal round is folded into the vote round: an authority's reveal
\*     is assumed to arrive wherever its vote arrives. In state.go a reveal
\*     can be lost on its own, and that authority is then left out of the
\*     certificate. That case is not explored.
\*   - The BLAKE2b shared-random value is abstracted to the chain of
\*     participant sets it derives from; equal chains give equal values.
\*   - The mix-parameter tally and pki.IsDocumentWellFormed (which refuses a
\*     document with an empty topology) are not modelled.
\*   - A Byzantine certificate relays an arbitrary set of votes, but the same
\*     set to every recipient. Commitments are signed, so it cannot forge one
\*     for an honest peer.
\*   - Byzantine authorities sign only documents computed by honest
\*     authorities. A document they invent can gather at most
\*     Cardinality(Byzantine) signatures, so this loses nothing given the
\*     assumption ByzantineMinority below.

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Auths,      \* set of authority identities
    Byzantine,  \* subset of Auths that may behave arbitrarily
    Nodes,      \* set of candidate mix-node descriptors that may be voted on
    MixLayers,   \* set of node sets, one per mix layer
    MinPerLayer, \* nodes a document needs from each mix layer
    RoleGroups,  \* node sets a document needs at least one of each
    MaxEpoch    \* number of consecutive epochs to model (>= 1)

Honest == Auths \ Byzantine

\* Strict majority, as votingThresholds() in state.go.
Threshold == (Cardinality(Auths) \div 2) + 1

ASSUME AuthsFinite       == IsFiniteSet(Auths)
ASSUME NodesFinite       == IsFiniteSet(Nodes)
ASSUME MixLayerSets      == MixLayers \subseteq SUBSET Nodes
ASSUME RoleGroupSets     == RoleGroups \subseteq SUBSET Nodes
ASSUME MinPerLayerPos    == MinPerLayer \in (Nat \ {0})
ASSUME MaxEpochPos       == MaxEpoch \in (Nat \ {0})
ASSUME ByzantineSubset   == Byzantine \subseteq Auths
ASSUME ByzantineMinority == Cardinality(Byzantine) < Threshold

\* Symmetry set for TLC. Only safe for invariant checking.
Symmetry ==
    Permutations(Honest) \cup Permutations(Byzantine) \cup Permutations(Nodes)

\* A shared-random value is the chain of links it derives from, oldest first.
\* computeSharedRandom() hashes in the previous epoch's value, or 32 zero bytes
\* when there is no previous document; the empty chain is that zero value.
SRVLink    == [epoch : 1..MaxEpoch, participants : SUBSET Auths]
SRVValue   == UNION {[1..k -> SRVLink] : k \in 0..MaxEpoch}
GenesisSRV == << >>

\* IsDocumentWellFormed (core/pki/document.go) refuses a document with an empty
\* topology or an empty layer, and one with no gateway node or no service node.
\* MixLayers is one node set per mix layer and a document needs MinPerLayer of
\* each; RoleGroups is one set for the gateways and one for the service nodes,
\* and a document needs at least one of each. Storage replicas are deliberately
\* neither: that function checks each replica descriptor and never counts them.
\*
\* MinPerLayer = 1 is what the reference enforces per epoch. The authority
\* config has a MinNodesPerLayer knob whose default is 2, and
\* hasEnoughDescriptors and verifyTopology in state.go would apply it, but
\* neither is called anywhere at e17bffb95, so it binds only the whitelist size
\* once in New(). MinPerLayer = 2 models what that knob asks for.
\*
\* With MixLayers and RoleGroups empty both conjuncts are vacuously true, so a
\* configuration that does not model document shape is unaffected.
WellFormed(S) ==
    /\ \A L \in MixLayers  : Cardinality(S \cap L) >= MinPerLayer
    /\ \A R \in RoleGroups : S \cap R # {}

\* A document fixes the epoch, the agreed descriptors, the authorities that
\* contributed shared randomness (srv), and the SRV it chains onto. NoDoc is
\* the "no document" value; its epoch 0 sets it apart from every document.
Doc   == [epoch : 1..MaxEpoch, desc : SUBSET Nodes,
          srv : SUBSET Auths, prior : SRVValue]
NoDoc == [epoch |-> 0, desc |-> {}, srv |-> {}, prior |-> GenesisSRV]

\* The shared-random value a document carries.
SRVof(D) == Append(D.prior, [epoch |-> D.epoch, participants |-> D.srv])

\* Byzantine authorities compute, finalise and chain onto nothing, so the
\* variables that record those things range over Honest only.
VARIABLES
    epoch,      \* current epoch number in 1..MaxEpoch
    phase,      \* "vote" -> "cert" -> "sig" -> "done"
    priorSRV,   \* [Honest -> SRVValue]     SRV each authority chains onto
    voteMsg,    \* [Auths -> [Auths -> SUBSET Nodes]]   voteMsg[a][b] = vote a sent to b
    recvVote,   \* [Auths -> SUBSET Auths]  whose votes each authority received
    recvCert,   \* [Honest -> SUBSET Auths] whose certificates each accepted
    myDoc,      \* [Honest -> Doc \cup {NoDoc}]  document each computed
    sigSet,     \* [Auths -> SUBSET Doc]    documents each authority signed
    finalDoc    \* [Honest -> Doc \cup {NoDoc}]  document each finalised

vars == <<epoch, phase, priorSRV, voteMsg, recvVote, recvCert, myDoc, sigSet,
          finalDoc>>

TypeOK ==
    /\ epoch \in 1..MaxEpoch
    /\ phase \in {"vote", "cert", "sig", "done"}
    /\ priorSRV \in [Honest -> SRVValue]
    /\ voteMsg  \in [Auths -> [Auths -> SUBSET Nodes]]
    /\ recvVote \in [Auths -> SUBSET Auths]
    /\ recvCert \in [Honest -> SUBSET Auths]
    /\ myDoc    \in [Honest -> Doc \cup {NoDoc}]
    /\ sigSet   \in [Auths -> SUBSET Doc]
    /\ finalDoc \in [Honest -> Doc \cup {NoDoc}]

\* Prod(D, f) is the set of functions g with domain D and g[a] \in f[a]. It
\* lets TLC enumerate per-authority choices directly, instead of generating
\* every function and filtering.
RECURSIVE Prod(_, _)
Prod(D, f) ==
    IF D = {} THEN {<< >>}
    ELSE LET a == CHOOSE x \in D : TRUE
         IN  {(a :> v) @@ g : v \in f[a], g \in Prod(D \ {a}, f)}

\* The votes of one epoch. An honest authority sends its descriptor view to
\* everyone; a Byzantine authority may send each recipient something different.
VoteAssignments ==
    {[a \in Auths |-> IF a \in Honest THEN [b \in Auths |-> hv[a]] ELSE bm[a]] :
        hv \in [Honest -> SUBSET Nodes],
        bm \in [Byzantine -> [Auths -> SUBSET Nodes]]}

Init ==
    /\ epoch = 1
    /\ phase = "vote"
    /\ priorSRV = [a \in Honest |-> GenesisSRV]
    /\ voteMsg \in VoteAssignments
    /\ recvVote = [a \in Auths  |-> {}]
    /\ recvCert = [a \in Honest |-> {}]
    /\ myDoc    = [a \in Honest |-> NoDoc]
    /\ sigSet   = [a \in Auths  |-> {}]
    /\ finalDoc = [a \in Honest |-> NoDoc]

\* Round 1: deliver votes. Each authority receives the votes of an arbitrary
\* set of authorities that includes itself. For a Byzantine authority the set
\* is whatever its certificate will claim.
VoteChoices(a) == {S \in SUBSET Auths : a \in S}

\* A restriction of VoteChoices for instances too large to search
\* exhaustively, substituted for it in a configuration file. Every honest
\* authority receives exactly Threshold votes, the Byzantine ones among them.
\* Every run of the restricted specification is a run of the full one, so a
\* counterexample found this way is genuine. An invariant that passes this way
\* is NOT thereby established. It must not mention VoteChoices, which it
\* replaces.
MinimalVoteChoices(a) ==
    IF a \in Byzantine THEN {{a}}
    ELSE {S \in SUBSET Auths :
             /\ {a} \cup Byzantine \subseteq S
             /\ Cardinality(S) = Threshold}

\* A restriction of VoteAssignments for the shape configurations, substituted
\* for it in a configuration file. One node is singled out: each honest
\* authority either holds every node or every node but that one, and a
\* Byzantine authority reports every node to some recipients and every node but
\* that one to the rest. Every run of the restricted specification is a run of
\* the full one, so a counterexample found this way is genuine. An invariant
\* that passes this way is NOT thereby established.
MinimalVoteAssignments ==
    {[a \in Auths |->
        IF a \in Honest
        THEN LET v == IF a \in H THEN Nodes ELSE Nodes \ {n}
             IN  [b \in Auths |-> v]
        ELSE [b \in Auths |-> IF b \in R THEN Nodes ELSE Nodes \ {n}]] :
        n \in Nodes, H \in SUBSET Honest, R \in SUBSET Auths}

DeliverVote ==
    /\ phase = "vote"
    /\ recvVote' \in Prod(Auths, [a \in Auths |-> VoteChoices(a)])
    /\ phase' = "cert"
    /\ UNCHANGED <<epoch, priorSRV, voteMsg, recvCert, myDoc, sigSet, finalDoc>>

\* Round 2: deliver certificates and compute documents.
\*
\* An honest authority issues a certificate only if it holds Threshold votes
\* (tallyVotes); a Byzantine one always can. A certificate is accepted only
\* from a peer whose vote arrived (onCertUpload). An authority that issued one
\* holds its own. One that did not computes no document, so what it accepts is
\* irrelevant and pinned to {}.
Certifiers ==
    Byzantine \cup {h \in Honest : Cardinality(recvVote[h]) >= Threshold}

CertChoices(a) ==
    IF a \in Certifiers
    THEN {S \in SUBSET (recvVote[a] \cap Certifiers) : a \in S}
    ELSE {{}}

\* The commitments b has seen attributed to a in the certificates it holds
\* (verifyCommits). None: b never learned of a. One: a participates in the
\* shared random. Several: a equivocated and is excluded.
Reported(b, a) ==
    {voteMsg[a][c] : c \in {cc \in recvCert[b] : a \in recvVote[cc]}}

Participants(b) == {a \in Auths : Cardinality(Reported(b, a)) = 1}

\* Descriptors with Threshold votes among those b received directly
\* (tallyVotes). Equivocators are not excluded, as in the implementation.
DescTally(b) ==
    {n \in Nodes :
        Cardinality({a \in recvVote[b] : n \in voteMsg[a][b]}) >= Threshold}

\* The document b computes, or NoDoc if it lacks Threshold certificates or
\* Threshold consistent commitments (getMyConsensus). The Threshold-votes gate
\* of tallyVotes is implied: every certificate b holds is from a peer whose
\* vote it holds.
DocOf(b) ==
    IF /\ Cardinality(recvCert[b]) >= Threshold
       /\ Cardinality(Participants(b)) >= Threshold
       /\ WellFormed(DescTally(b))
    THEN [epoch |-> epoch, desc |-> DescTally(b),
          srv |-> Participants(b), prior |-> priorSRV[b]]
    ELSE NoDoc

DeliverCert ==
    /\ phase = "cert"
    /\ UNCHANGED <<epoch, priorSRV, voteMsg, recvVote, sigSet, finalDoc>>
    /\ recvCert' \in Prod(Honest, [a \in Honest |-> CertChoices(a)])
    /\ myDoc' = [a \in Honest |-> DocOf(a)']
    /\ phase' = "sig"

\* Round 3: deliver signatures and finalise.
\*
\* An honest authority signs the document it computed, if any. A Byzantine
\* authority signs any set of documents honest authorities computed.
\*
\* An authority finalises iff the signatures delivered to it include Threshold
\* over its own document. Delivery is an arbitrary subset, so an authority
\* whose document holds Threshold signatures may or may not finalise, and one
\* whose document holds fewer cannot. The delivery sets are not recorded;
\* nothing else depends on them. An authority always holds its own signature,
\* so with Threshold = 1 it cannot fail to finalise.
HonestDocs == {myDoc[h] : h \in Honest} \ {NoDoc}

\* Every document that holds Threshold signatures, delivered or not.
EpochConsensus ==
    {D \in HonestDocs :
        Cardinality({a \in Auths : D \in sigSet[a]}) >= Threshold}

DeliverSig ==
    /\ phase = "sig"
    /\ UNCHANGED <<epoch, priorSRV, voteMsg, recvVote, recvCert, myDoc>>
    /\ \E bs \in [Byzantine -> SUBSET HonestDocs] :
         sigSet' = [a \in Auths |->
                       IF a \in Honest THEN {myDoc[a]} \ {NoDoc} ELSE bs[a]]
    /\ LET able == {a \in Honest : myDoc[a] \in EpochConsensus'}
       IN  \E fin \in SUBSET able :
              /\ (Threshold = 1) => (fin = able)
              /\ finalDoc' = [a \in Honest |->
                                 IF a \in fin THEN myDoc[a] ELSE NoDoc]
    /\ phase' = "done"

\* Epoch boundary.
\*
\* An authority that finalised chains onto its own document
\* (getThresholdConsensus stores it). One that did not goes through
\* stateBootstrap and backgroundFetchConsensus(). The fetch may land, giving it
\* a document a peer can serve, or may not land before it votes, in which case
\* it restarts the chain from the zero value. Honest peers serve the document
\* they finalised; a Byzantine peer can serve any document that holds
\* Threshold signatures.
Fetchable ==
    ({finalDoc[h] : h \in Honest} \ {NoDoc})
        \cup (IF Byzantine = {} THEN {} ELSE EpochConsensus)

PriorChoices(a) ==
    IF finalDoc[a] # NoDoc THEN {SRVof(finalDoc[a])}
    ELSE {SRVof(D) : D \in Fetchable} \cup {GenesisSRV}

EpochAdvance ==
    /\ phase = "done"
    /\ epoch < MaxEpoch
    /\ epoch' = epoch + 1
    /\ phase' = "vote"
    /\ priorSRV' \in Prod(Honest, [a \in Honest |-> PriorChoices(a)])
    /\ voteMsg' \in VoteAssignments
    /\ recvVote' = [a \in Auths  |-> {}]
    /\ recvCert' = [a \in Honest |-> {}]
    /\ myDoc'    = [a \in Honest |-> NoDoc]
    /\ sigSet'   = [a \in Auths  |-> {}]
    /\ finalDoc' = [a \in Honest |-> NoDoc]

\* Terminal: the last epoch has finished.
Done ==
    /\ phase = "done"
    /\ epoch = MaxEpoch
    /\ UNCHANGED vars

Next == DeliverVote \/ DeliverCert \/ DeliverSig \/ EpochAdvance \/ Done

Spec == Init /\ [][Next]_vars

\* Properties.

\* No two honest authorities finalise different documents.
Agreement ==
    \A a, b \in Honest :
        (finalDoc[a] # NoDoc /\ finalDoc[b] # NoDoc)
            => (finalDoc[a] = finalDoc[b])

\* At most one document per epoch holds Threshold signatures. Stronger than
\* Agreement: it also covers a document that no honest authority finalised
\* but that a Byzantine authority could still serve.
UniqueConsensus == Cardinality(EpochConsensus) <= 1

\* Every descriptor in a document an honest authority computes was in some
\* honest authority's vote. Byzantine authorities cannot inject one.
DescriptorValidity ==
    \A a \in Honest :
        \A n \in myDoc[a].desc : \E h \in Honest : n \in voteMsg[h][h]

\* The SRV chain does not fork: honest authorities that chain onto a prior
\* document chain onto the same value. An authority on the zero value has
\* restarted the chain, not forked it.
ChainConsistency ==
    \A a, b \in Honest :
        (priorSRV[a] # GenesisSRV /\ priorSRV[b] # GenesisSRV)
            => (priorSRV[a] = priorSRV[b])

\* The chain an honest authority builds on consists of consecutive epochs
\* ending at the previous one.
ChainGrounded ==
    \A a \in Honest :
        LET c == priorSRV[a]
        IN  \A i \in 1..Len(c) : c[i].epoch + (Len(c) - i) + 1 = epoch

\* All honest authorities chain onto the same value. EXPECTED TO FAIL even
\* with no Byzantine authority: one honest authority fails to finalise and
\* its fetch does not land. Checked to obtain that trace.
ChainUnanimity == \A a, b \in Honest : priorSRV[a] = priorSRV[b]

\* With every vote and certificate delivered and a common prior, all honest
\* authorities compute the same document. Holds only while no Byzantine
\* authority equivocates; its failure in a Byzantine configuration is the
\* descriptor-equivocation attack described in the README.
ConvergenceUnderFullDelivery ==
    (/\ phase \in {"sig", "done"}
     /\ \A a \in Honest : recvVote[a] = Auths /\ recvCert[a] = Auths
     /\ ChainUnanimity)
        => \A a, b \in Honest : myDoc[a] # NoDoc /\ myDoc[a] = myDoc[b]

\* EXPECTED TO FAIL. The counterexample is a run in which every honest
\* authority finalises the same document, i.e. a successful consensus.
ConsensusUnreachable ==
    ~ \A a, b \in Honest : finalDoc[a] # NoDoc /\ finalDoc[a] = finalDoc[b]

\* NOT CHECKED, because they are tautologies under this encoding:
\*   - "Validity" (a finalised document was computed by some honest
\*     authority): DeliverSig assigns finalDoc'[a] to myDoc[a] or NoDoc.
\*   - "Integrity" (a finalised document carries Threshold signatures): that
\*     is the guard that produces finalDoc'.
\*   - "Honest randomness" (every shared-random value has an honest
\*     contributor): the authority computing a document is always one of its
\*     own participants.
\* Making Integrity meaningful would require signatures to accumulate over
\* several steps, as getThresholdConsensus() does when it re-attempts
\* cert.VerifyThreshold on each arriving signature.

=============================================================================
