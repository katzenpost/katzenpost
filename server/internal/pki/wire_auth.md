# Wire authentication by component (review draft)

This draft describes the code at `dbcfd83b` and the server link-key fix in
this change. It is not a new wire format or a complete authentication audit.
Source paths below are relative to the repository root.

## Boundary and trust model

`core/wire/session.go` uses Nyquist `pattern.PqXX`, the configured KEM,
ChaChaPoly and BLAKE2b. It constructs `PeerCredentials` from the handshake's
remote static KEM key and authenticated additional data, then invokes
`PeerAuthenticator.IsPeerValid`. Failure terminates the handshake. Possession
of a link private key does not by itself authorize a node identity, topology
edge, component role or command. Those bindings are component policy.

The trust inputs are configured authority keys and verified PKI documents.
This review considers an untrusted peer presenting arbitrary additional data
or its own link key, plus legitimate peers during key rotation, topology
changes and delayed consensus publication. Compromised authorities, consensus
validation, packet replay handling, PAKE security and traffic-analysis
resistance are outside this patch. Link authentication alone is not an
anonymity guarantee.

The [wire specification](https://katzenpost.network/docs/specs/pdf/wire.pdf)
describes the handshake authentication boundary. The implementation, including
its PQ pattern, is the reference for this draft; generic Noise XX/IK examples
must not be substituted for it.

## Mix server, gateway and service node links

Sources: `server/internal/pki/pki.go`, `server/internal/pkicache/pkicache.go`,
`server/internal/incoming/incoming_conn.go`,
`server/internal/outgoing/outgoing_conn.go`.

`AuthenticateConnection` requires additional data of exactly `NodeIDLength`
bytes, representing the hash of the node identity key. Documents are supplied
newest first by `documentsForAuthentication`: current epoch, retained past
epochs, and next epoch when admitted by the early-connect policy. Cache
entries expose different incoming and outgoing adjacency maps.

For each direction-eligible descriptor for the requested identity:

1. Remember the first descriptor as the newest eligible descriptor.
2. Accept a link-key match against either this document's descriptor or that
   newest eligible descriptor. A key from a different identity or an
   ineligible direction cannot supply the fallback.
3. Apply the document's epoch policy below. A key match alone is insufficient.

| Authorizing document | Connection valid | Traffic permitted |
| --- | --- | --- |
| Current epoch | Yes | Yes |
| Next epoch only | Yes | Incoming only when `till < Period/8`; outgoing waits |
| Retained past epoch | Only if a current document exists and still lists the identity | Yes, under the same condition |
| No matching key or no eligible descriptor | No | No |

The table describes each document's contribution. Evaluation continues after
a next-epoch match that cannot yet send: a current or eligible past document
may authorize traffic. A future-listed identity that was removed from the
current document may retain a valid waiting connection; its past membership
does not permit sending. The current membership check for past topology is
`GetByID`, deliberately not a current adjacency check, so old routes can drain
while their mix keys remain usable.

The returned descriptor is the newest direction-eligible descriptor, not
necessarily the descriptor whose key matched. Consumers must check `isValid`.
The rewrite also rejects absent credentials/keys and serialization failures.

### Why restore the newest-key alternative

Previously, the inner mismatch condition repeated the outer comparison. It
could never authorize a descriptor using the newest descriptor's key. For
example, a next-epoch descriptor can advertise key B while a current descriptor
still has key A. A connection proving B should be able to use current topology
under the documented fallback, rather than remaining unable to send.

The same rule permits a newly advertised key to use retained past topology,
provided the identity remains in the current document. Keeping support for
the individual document's key also preserves the existing grace behavior for
old keys. This is not immediate revocation of all older link keys on rotation.

Outgoing connections additionally pin the expected destination identity and
link key in `outgoingConn.IsPeerValid` before consulting PKI. The new fallback
does not override that pin. Incoming gateways first try mix authentication,
then their client policy. In this revision `gateway.AuthenticateClient`
accepts any completed wire handshake: a failed mix check does not necessarily
mean that a gateway rejects the connection as a client. That policy is unchanged.

## Client

`client/connection.go` authenticates its gateway by exact descriptor link-key
and identity-hash comparisons. Its session sends the client's queue ID as
additional data. Client admission at the gateway is distinct from authenticating
the gateway to the client. Local thin-client daemon access is a separate
boundary, not this link authentication function.

## Courier and replica

`courier/server/outgoing_conn.go` pins the selected replica's identity and key,
then calls `courier/server/pki.go:AuthenticateReplicaConnection`. That PKI
function also supports matching descriptors in cached adjacent epochs.

`replica/incoming_conn.go:IsPeerValid` distinguishes an empty additional-data
field (courier) from a node-ID-length field (replica). Courier authentication
checks the key advertised by a service node's courier capability in the
selected PKI document. Replica authentication checks the identity lookup and
link key. `replica/outgoing_conn.go` has its own destination/PKI checks and
reauthentication policy. Their cache selection and grace behavior are not
assumed identical to mix-server authentication and are not modified here.

## Directory authority

`authority/voting/client/client.go:authorityAuthenticator` checks the configured
authority identity-hash prefix and link key. On the authority server,
`wireAuthenticator` in `authority/voting/server/wire_handler.go` classifies
empty additional data as a client; hash-sized additional data selects a
configured mix/gateway/service, replica or authority identity. Authority peers
also require the configured link key. Mix and replica admission at that layer
does not independently bind their link key to a descriptor.

The command dispatcher separates those roles, and descriptor upload handlers
check signed uploads and identity bindings. Wire admission and authorization
of a signed operation must therefore be reviewed separately. This patch does
not change authority policy or Jake's authority fixes.

## PANDA

There is no PANDA implementation in the inspected `dbcfd83b` tree or its
module requirements. Its historical PAKE/service design must not be represented
as a verified current `core/wire` authenticator. Completing this section needs
the intended PANDA repository and revision and a trace of its service/plugin
transport. No PANDA cryptography or DoS changes are included in this patch.

## Validation and separate follow-up

`authentication_test.go` builds real `pkicache.Entry` topology maps and covers
both directions, key rotation, unrelated keys, wrong direction, absent
identity, the exact early-send boundary, missing current consensus, de-listing,
retained past epochs, malformed additional data and key serialization errors.
Restoring the previous always-reject-mismatch predicate must fail the newest
key regression cases. These are policy tests, not a full network handshake or
live-mixnet interoperability test.

Separate review item: `documentsForAuthentication` can return cached `till`
and a document selection made earlier in the epoch. The cache's early-window
freshness deserves an independent regression and fix. The policy tests here
use explicit snapshot time to test the comparator; they do not certify that
the snapshot tracks wall-clock transitions. This pre-existing cache behavior
is not changed by the one-cause link-key fix.
