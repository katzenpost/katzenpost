---------------------------- MODULE MixKeys ----------------------------
\* A TLA+ model of how a Katzenpost mix node rotates its mix keys and
\* rejects replayed packets.
\*
\* It follows server/internal/mixkeys (Generate, Prune, Shadow, Halt,
\* purgeStaleKeyFiles), server/internal/mixkey (IsReplay, Persist, Load),
\* server/internal/pki (publishDescriptorIfNeeded) and
\* server/internal/cryptoworker (doUnwrap).
\*
\* A mix key belongs to one epoch. Once per epoch, while it prepares the
\* descriptor for the next epoch, the PKI worker generates the keys of the
\* next NumMixKeys epochs and prunes those older than the previous epoch. It
\* then tells every crypto worker to copy the key set again. Apart from
\* start-up, generating and pruning happen nowhere else.
\*
\* A crypto worker tries the keys of the previous, current and next epoch on
\* each packet. Each key carries its own replay filter, shared by all
\* workers, and testing and setting a tag is one atomic step.
\*
\* The constant MaxSkips is the number of epochs that may pass without the
\* publish step. In the implementation an epoch passes without it when its
\* upload window has closed, when the step fails before it reaches the keys,
\* or when the node has stopped advertising itself before a shutdown.
\*
\* The constant Restarts lets the node shut down cleanly and boot again with
\* PersistMixKeysOnShutdown set. On shutdown every key is written to a file.
\* On boot the files of the current epoch and the two after it are loaded,
\* and every other file is removed. A file holds the private key and nothing
\* else, so a loaded key starts with an empty replay filter.
\*
\* ABSTRACTIONS / OUT OF SCOPE:
\*   - A packet is a key epoch and a replay tag. Cryptography is symbolic: a
\*     packet unwraps under the key of its epoch and no other.
\*   - Every worker copies the key set within the epoch in which it was told
\*     to. The call that tells it is blocking, and a worker answers as soon as
\*     it has finished its current packet.
\*   - The clock never goes backwards.
\*   - A replay filter is exact. The implementation uses a Bloom filter, which
\*     may also reject a fresh tag.
\*   - A restart without saved keys is not modelled, nor is a crash. The
\*     node then begins with fresh keys, which no earlier packet unwraps
\*     under.

EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    Workers,    \* crypto workers
    Tags,       \* replay tags
    MaxEpoch,   \* last epoch to explore
    MaxSkips,   \* how many epochs may pass without the publish step
    Restarts    \* TRUE: the node may shut down and boot with its keys saved

ASSUME MaxEpoch \in Nat \ {0} /\ MaxSkips \in Nat /\ Restarts \in BOOLEAN

Symmetry == Permutations(Workers) \cup Permutations(Tags)

\* constants.NumMixKeys
NumMixKeys == 3

Epochs == 0 .. (MaxEpoch + NumMixKeys)

VARIABLES
    epoch,      \* the current epoch
    published,  \* the publish step has run in this epoch
    skips,      \* how many epochs have passed without it
    keys,       \* the key set of the node: the epochs it holds a key for
    shadow,     \* [Workers -> SUBSET Epochs]  each worker's copy of it
    pending,    \* [Workers -> BOOLEAN]  the worker was told to copy again
    seen,       \* [Epochs -> SUBSET Tags]  the replay filter of each key
    accepts,    \* [Epochs \X Tags -> 0..2]  acceptances, capped at 2
    down,       \* the node is shut down
    files       \* the epochs with a key file on disk

vars == <<epoch, published, skips, keys, shadow, pending, seen, accepts,
          down, files>>

TypeOK ==
    /\ epoch \in 1 .. MaxEpoch
    /\ published \in BOOLEAN
    /\ skips \in 0 .. MaxSkips
    /\ keys \subseteq Epochs
    /\ shadow \in [Workers -> SUBSET Epochs]
    /\ pending \in [Workers -> BOOLEAN]
    /\ seen \in [Epochs -> SUBSET Tags]
    /\ accepts \in [Epochs \X Tags -> 0 .. 2]
    /\ down \in BOOLEAN
    /\ files \subseteq Epochs

\* A node starts with the keys of the current epoch and the two after it
\* (mixKeys.init).
Init ==
    /\ epoch = 1
    /\ published = FALSE
    /\ skips = 0
    /\ keys = 1 .. NumMixKeys
    /\ shadow = [w \in Workers |-> keys]
    /\ pending = [w \in Workers |-> FALSE]
    /\ seen = [k \in Epochs |-> {}]
    /\ accepts = [x \in Epochs \X Tags |-> 0]
    /\ down = FALSE
    /\ files = {}

Settled == \A w \in Workers : ~pending[w]

\* The publish step (publishDescriptorIfNeeded): Generate for the next epoch,
\* then Prune, then tell the workers if anything changed. It runs at most
\* once per epoch, and waits for the workers before it returns.
Publish ==
    /\ ~down /\ ~published /\ Settled
    /\ published' = TRUE
    /\ keys' = (keys \cup ((epoch + 1) .. (epoch + NumMixKeys)))
                  \ {k \in keys : k < epoch - 1}
    /\ pending' = [w \in Workers |-> keys' # keys]
    /\ UNCHANGED <<epoch, skips, shadow, seen, accepts, down, files>>

\* A worker copies the key set (Shadow).
Reshadow(w) ==
    /\ ~down /\ pending[w]
    /\ shadow' = [shadow EXCEPT ![w] = keys]
    /\ pending' = [pending EXCEPT ![w] = FALSE]
    /\ UNCHANGED <<epoch, published, skips, keys, seen, accepts, down, files>>

\* The epoch ends. A node that is down publishes nothing, and that is not
\* counted as a skip.
NextEpoch ==
    /\ epoch < MaxEpoch /\ Settled
    /\ down \/ published \/ skips < MaxSkips
    /\ epoch' = epoch + 1
    /\ published' = FALSE
    /\ skips' = IF down \/ published THEN skips ELSE skips + 1
    /\ UNCHANGED <<keys, shadow, pending, seen, accepts, down, files>>

\* Worker w accepts a packet built for key epoch k with replay tag t
\* (doUnwrap). It needs the key of the current epoch, tries that key and its
\* two neighbours, and accepts only if the tag is new to the key's filter.
\* A packet that is not accepted is dropped, which changes nothing.
Accept(w, k, t) ==
    /\ ~down
    /\ epoch \in shadow[w]
    /\ k \in {epoch - 1, epoch, epoch + 1} \cap shadow[w]
    /\ t \notin seen[k]
    /\ seen' = [seen EXCEPT ![k] = @ \cup {t}]
    /\ accepts' = [accepts EXCEPT ![<<k, t>>] = IF @ < 2 THEN @ + 1 ELSE @]
    /\ UNCHANGED <<epoch, published, skips, keys, shadow, pending, down, files>>

\* A clean shutdown (Halt). Every key the node holds is written to a file.
\* The process ends, and its replay filters end with it.
Shutdown ==
    /\ Restarts /\ ~down /\ Settled
    /\ down' = TRUE
    /\ files' = keys
    /\ keys' = {}
    /\ shadow' = [w \in Workers |-> {}]
    /\ seen' = [k \in Epochs |-> {}]
    /\ UNCHANGED <<epoch, published, skips, pending, accepts>>

\* The next boot (init). Files outside the current epoch and the two after
\* it are removed. Generate then loads a key from its file, which removes the
\* file, or makes a fresh key where there is none.
Boot ==
    /\ down
    /\ down' = FALSE
    /\ files' = {}
    /\ keys' = epoch .. (epoch + NumMixKeys - 1)
    /\ shadow' = [w \in Workers |-> keys']
    /\ published' = FALSE
    /\ UNCHANGED <<epoch, skips, pending, seen, accepts>>

Next ==
    \/ Publish \/ NextEpoch \/ Shutdown \/ Boot
    \/ \E w \in Workers :
          \/ Reshadow(w)
          \/ \E k \in Epochs, t \in Tags : Accept(w, k, t)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* Properties.

\* The key of epoch k still exists somewhere: in the node, in a worker, or in
\* a file. In memory a key is destroyed when the last holder lets go of it
\* (Deref).
Alive(k) ==
    k \in keys \/ k \in files \/ \E w \in Workers : k \in shadow[w]

\* No packet is accepted twice. Without restarts this holds by construction:
\* a tag is accepted only if it is new to the filter, accepting it records
\* it, and the filter never shrinks. A restart is what can break it.
ReplayFreedom == \A x \in Epochs \X Tags : accepts[x] <= 1

\* Forward secrecy: the key of epoch k is destroyed before epoch k + 3
\* begins. It is last usable in epoch k + 1, and the publish step of epoch
\* k + 2 prunes it.
KeysDestroyedOnTime == \A k \in Epochs : Alive(k) => k + 2 >= epoch

\* While the node runs, every worker holds the keys of the current and the
\* next epoch, so that no packet built for either is refused for lack of a
\* key.
KeysAvailable ==
    ~down => \A w \in Workers : {epoch, epoch + 1} \subseteq shadow[w]

\* EXPECTED TO FAIL. Each is checked to obtain a witness trace.

\* Violated by a packet that is accepted.
NeverAccepts == \A x \in Epochs \X Tags : accepts[x] = 0

\* Violated by a key that is destroyed.
NeverDestroys == \A k \in 1 .. NumMixKeys : Alive(k)

=============================================================================
