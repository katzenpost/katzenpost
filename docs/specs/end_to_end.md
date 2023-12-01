---
title: "End-to-end Protocol"
linkTitle: ""
description: ""
categories: [""]
tags: [""]
author: ["Yawning Angel", "George Danezis", "Claudia Diaz", "Ania Piotrowska", "David Stainton"]
version: 0
draft: true
---

**Abstract**

This is a specification for the Katzenpost/LEAP mix network client end
to end protocol and egress mix behavior. The mix network specification
is described in Katzenpost Mix Network Specification
[KATZMIXNET](#KATZMIXNET){.citation}. The protocols used by mixes to
publish their identities is described in the Katzenpost Mix Network PKI
Specification [KATZMIXPKI](#KATZMIXPKI){.citation}.

## 1. Introduction

Fundamentally a mix network is a lossy packet switching network on which
we can build reliable protocols. We therefore utilize a variety of ideas
from both the mix network and classical internet protocol literature to
design an end to end reliability protocol that utilizes the mix network.

### 1.1. Terminology

- `ACK` - A protocol acknowledgment of a previously sent Block.
- `ARQ` - Automatic Repeat reQuest is an error correction method which
  requires two-way communication and incurs a delay penalty when used.
- Classes of traffic - We distinguish the following classes of
  traffic:
  -   ACKs
  -   Forward messages
- `Block` - A fragment of a message that fits into a single packet of
  a specified class of traffic.
- `Block ID` - A unique identifier for a Block.
- `Client` - Software run by the human being on its local device.
- `E2E Encrypted message` - An encrypted message.
- `Message` - A variable size end-to-end message, transmitted from one
  location to another. The message can be classified into one of the
  classes of traffic, depending on the message size, and transported
  as a single packet or divided into several packets.
- `Message ID` - A unique identifier for a message.
- `Mix` - A server that provides anonymity to clients by accepting
  messages encrypted to its public key, which it then decrypts, delays
  for a given amount of time, and transmits either to another mix or
  to a provider (as specified in the messages). Those operations
  provide bitwise unlinkability between input and output messages as
  well as long term correlation resistance.
- `Provider` - The provider is a client\'s single point of failure for
  participating in the mix network because it is responsible for
  authorising sent messages as well as storing received messages on
  behalf of the user. Provider MUST perform the same cryptographic
  operations as the Mix.
- `Packet` - A Sphinx packet.The Katzenpost system supports multiple
  packet sizes for different classes of traffic. In particular:
  -   `XKB-block: XX KB` (to-do: specify the number of KB)
  -   `YKB-block: YY KB` (to-do: specify the number of KB/MB)
- `SURB-ACK` - A short message notifying that a packet was delivered;
  transmitted via a Single Use Reply Block
  [SPHINX](#SPHINX){.citation}.
- `SURB_SIZE = sizeof(SphinxSURB)` where `SphinxSURB` is a Single Use
  Reply Block defined in the "Sphinx Mix Network Cryptographic Packet
  Format Specification".

### 1.2 Conventions Used in This Document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
[RFC2119](#RFC2119){.citation}.

The "C" style Presentation Language as described in
[RFC5246](#RFC5246){.citation} Section 4 is used to represent data
structures, except for cryptographic attributes, which are specified as
opaque byte vectors.

- `byte` - An 8-bit octet.

### 1.3 Constants

- `BLOCK_LENGTH` - The maximum payload size of a block (message fragment). The value of `BLOCK-LENGTH` depends on the class of traffic.

## 2. Mix Network Packet Format Considerations

As the mix network message packet format we use Sphinx, as specified:
"Sphinx Mix Network Cryptographic Packet Format Specification",
[SPHINXSPEC](#SPHINXSPEC){.citation}.

The Sphinx cryptographic primitives and parameters are specified in
Section 3 of: "The Katzenpost Mix Network Specification",
[KATZMIXNET](#KATZMIXNET){.citation}.

## 3. Client and Provider Core Protocol

All client mixnet interaction happens through their Provider, reusing
the existing trust relationship any given user may have with an e-mail
service provider, and all client to Provider interaction will use the
Katzenpost Mix Network Wire Protocol, described in "Katzenpost Mix
Network Wire Protocol Specification",
[KATZMIXWIRE](#KATZMIXWIRE){.citation}.

### 3.1 Handshake and Authentication

Let the contents of the wire protocol AuthenticateMessage's
`additional_data` field consist of the local-part component of a
client\'s e-mail address if the client is authenticating, padded with
NUL bytes to exactly 64 bytes in length.

In the case that the authenticating party is a Provider instance, let
the `additional_data` field contain the domain name that the Provider is
responsible for mail for.

### 3.2 Client Retrieval of Queued Messages

Clients periodically poll their Provider for messages that may have been
enqueued in that user's mailbox. All wire protocol commands including
these defined commands MUST come after the above described handshake and
authentication. We define two additional wire protocol commands:

```
enum {
    /* Extending the wire protocol Commands. */
    retrieve_message(16),
    message(17),
} Command;
```

The structures of these commands are defined as follows:

```
struct {
    uint32_t sequence_number;
} RetrieveMessage;

enum {
    ack(0),
    message(1),
    empty(2),
} message_type;

struct {
    opaque surb_id[SURB_ID_LENGTH];
    opaque encrypted_payload[SURB_PAYLOAD_LENGTH];
} Ack;

struct {
    opaque encrypted_payload[PAYLOAD_LENGTH];
    opaque padding[sizeof(Ack) - PAYLOAD_LENGTH];
} MessageCiphertext;

struct {
    message_type type;
    uint8_t queue_size_hint;
    uint32 sequence_number;
    select (message_type) {
        case ack:    Ack;
        default:     MessageCiphertext;
    };
} Message;
```

### 3.2.1 The retrieve_message and message Commands

Once a client is connected to the Provider and has entered the data
transfer phase after completing the handshake and authentication, the
client may start to retrieve messages from the provider via issuing the
`retrieve_message` command.

The `retrieve_message` command contains a sequence number which the
client initially sets to `0` at the beginning of each session. This
sequence number is incremented each time the client receives a message
from the provider (as a message command), except if the `message_type`
is `empty` indicating that the client\'s inbound message queue is empty,
as no message has been received.

Clients MUST NOT have more than one outstanding retrieve_message command
at a given time.

The Provider MUST respond to retrieve_message commands, in the following
manner:

1. Validate that the `sequence_number` is in the expected range, and
   that there are no other `retrieve_message` commands originating from
   a particular session being serviced. If the `sequence_number` is
   unexpected, or the client is issuing multiple `retrieve_message`
   commands, the session MUST be terminated.
2. If the sequence_number has been incremented, indicating that the
   client has received the last `message` reply, remove the 0th message
   from the client's message queue and delete it securely.
3. Send a message command as a response, with the following values for
   the `Message` fields (as the command's payload).
   - `type` - The type of the message that is being transported.
   - `queue_size_hint` - The size of the client\'s inbound message
     queue, excluding the message currently being sent, clamped to 255.
   - `sequence_number` - The sequence number of the retrieve_message.

If the 0th message is a SURB-ACK:

- `surb_id` - The SURB\'s identifier taken from the SURBReplyCommand in the Sphinx packet header that delivered the SURB.

If the message type empty, a `MessageCiphertext` is still embedded
in the Message structure, however the contents MUST be zero filled
(filled with `0x00` bytes).

Clients MAY use the `queue_size_hint` to determine if additional
retreive_message commands should be issued soon, or if they can delay
the next retreive_message under the assumption that the queue is empty.

Providers SHOULD attempt to service `retrieve_message` commands in a
timely manner.

## 4. Client and Provider processing of received packets

This section describes the protocol that reliably transmits messages
across the mix network to the destination Provider.

It is assumed that all clients have a long lived X25519 keypair, the
public component of which is known in advance to all peers who wish to
communicate securely with them. How to distribute such keying
information is beyond the scope of this document.

Messages begin at the sender as byte strings containing an e-mail in the
Internet Message Format (IMF) [\[RFC5322\]](#RFC5322){.citation}.

*NOTE: Should we make clients set any header fields, or reserve header fields
for use by the recipient?)*

Preparing a message for transport takes the following steps:

### 1. The message is fragmented into block(s).

The block structure is as follows:

```
struct {
    opaque message_id[16];
    uint16_t total_blocks;
    uint16_t block_id;
    uint32_t block_length;
    opaque block[block_length];
    opaque padding[BLOCK_LENGTH-block_length]; /* 0x00s */
} Block;
```

Where:

- `message_id` - A unique identifier, consistent across all Block(s) belonging to a given message.
- `total_blocks` - The number of Block(s) that make up the fully reassembled message.
- `block_id` - The sequence number of the Block as a component of a stream of Block(s) making up a message, starting at `0`.
- `block_length` - The length of the Block\'s message fragment.
- `block` - The Block\'s message fragment.
- `padding` - Padding, applied to the terminal Block.

The padding if any MUST contain `0x00s` (ie: be zero padded).

The `message_id` SHOULD be trivially collision resistant, and SHOULD
NOT be reused while there is a possibility that the recipient can
end up Block(s) belonging to multiple messages with a colliding
`message_id`.

### 2. Encrypt and authenticate each block.

Each Block is encrypted and authenticated as a Noise protocol
[NOISE](#NOISE){.citation} handshake plus transport message,
using the recipient's long term X25519 public key, the sender's
long term X25519 keypair, and a freshly generated ephemeral X25519
keypair.

`Noise_X_25519_ChaChaPoly_Blake2b` is used as the Noise protocol
name and parameterization for the purpose of Block encryption.

Let the encrypted and authenticated Block be referred to as the
following:

```
struct {
    /* Noise protocol fields. */
    opaque noise_e[32];     /* The Noise handshake `e`. */
    opaque noise_s_mac[16]; /* The Noise handshake `s` MAC. */
    opaque noise_s[32];     /* The Noise handshake `s`. */
    opaque noise_mac[16];   /* The Noise ciphertext MAC. */
    opaque ciphertext[BLOCK_LENGTH];
} BlockCiphertext;
```

### 3. Derive the path(s) and delays for each block.

Prior to the creation of the Sphinx packet(s) that will transport
each message, it is necessary to pre-calculate the forward and
optional return path(s), for each BlockCiphertext and it\'s optional
associated SURB-ACK.

While the sender\'s provider is not, strictly speaking a \"mix\", it
will apply Sphinx packet processing as if it is a mix, and therefore
MUST have a delay.

The recipient\'s provider MUST NOT have a delay.

See `Section 5.1 <5.1>`{.interpreted-text role="ref"} and
`Section 5.2 <5.2>`{.interpreted-text role="ref"} for details.

### 4. Create the SURB-ACK\'s Single Use Reply Block for each block (Optional).

To allow for reliable transmission we use acknowledgments
encapsulated in the Single-User Reply Blocks (SURB) of the Sphinx
packet format (see "The Sphinx Packet Format Specification"). We
refer to these as SURB-ACKs.

In order to create a SURB-ACK the Client uses the input obtained
from the PKI with all the addresses and public keys of the nodes,
where nodes include both providers and mixes.

The new path and set of delays for each SURB-ACK are selected
independently following Step 4.

This SURB-ACK is included in the Sphinx packet of the forward
message, in the payload that is received by the egress provider.

### 5. Assemble each BlockCiphertext and (Optional) SURBs into Sphinx packet payload.

Let the Sphinx packet payload consist of the following:

```
struct {
    uint8_t flags;
    uint8_t reserved; /* Set to 0x00. */
    select (flags) {
    case 0:
        opaque padding[sizeof(SphinxSURB)];
    case 1:
        SphinxSURB surb;
    }
    BlockCiphertext ciphertext[];
} BlockSphinxPlaintext;
```

All non-terminal hops MUST have a `NodeDelayCommand` and
`NextNodeHopCommand` command in the per-hop routing command vector.

The terminal hop for all forward Sphinx packets MUST have a
recipient command in the per-hop routing command vector containing
the recipient\'s identifier (the local-part of the recipient\'s
e-mail address).

The terminal hop of all SURB-ACKs MUST have a recipient command in
the per-hop command vector containing the sender\'s identifier, and
additionally have a surb_reply command containing the ID of the
SURB.

### 6. Send each Sphinx packet via the `send_packet` command.

Each Sphinx packet is then send out via the sender\'s Provider into
the mixnet, using the `send_packet` wire protocol command.

The sender SHOULD impose a random delay between each packet, and if
the sender chooses to implement this functionality such delay MUST
be factored into the path and delay derivation done in step 3.

### 7. Retransmit lost blocks as needed (Optional).

If the SURB-ACK functionality is used, the sender will receive a
SURB, containing an ACK, per block from the recipient's provider
signalling that the Sphinx packet has arrived, was successfully
processed, and queued for delivery to the recipient.

As the sender specifies all mixing delays in advance, the time that
a SURB-ACK should arrive for any given block is known to reasonable
accuracy in advance.

If the sender determines that a Sphinx packet was lost (for example
by the lack of a SURB-ACK at around the expected time, factoring in
potential additional network delays), it SHOULD retransmit the
block. The exact ARQ strategy used to determine when a block is
considered lost, and which blocks to retransmit is left up to the
implementation, however the following rules MUST be obeyed:

-   All retransmitted blocks MUST be re-encrypted, and have a
    entirely new set of paths and delays. In simple terms, this
    means re-doing the packet creation/transmission from step 2 for
    each retransmitted block.
-   Senders MUST NOT retransmit blocks at a rate faster than one
    block per 3 seconds.
-   Retransmissions must NOT have predictable timing otherwise it
    exposes the destination Provider to discovery by a powerful
    adversary that can perform active confirmation attacks.
-   Senders MUST NOT attempt to retransmit blocks indefinitely, and
    instead give up on the entire message after it fails to arrive
    after a certain number of retransmissions.

## 4.1 Provider Behavior for Receiving Messages from the Mix Network

All Providers MUST accept inbound connections from the final layer of
the mix network, and receive Sphinx packets. Upon receiving a Sphinx
packet, the provider MUST do the following things:

1.  Unwrap the Sphinx packet.

All unwrapped packets MUST have at least a recipient command in the
per-hop command vector specifying which client the packet is
destined for.

Providers MUST discard all packets that are either missing recipient
information, or that are addressed to unknown recipients with no
additional processing.

2.  Handle the unwrapped packet.

If the Sphinx packet did not have a `surb_reply` command in the
per-hop command vector, then the payload MUST be interpreted as a
`BlockSphinxPlaintext` as follows:

1.  The Provider queues the packet\'s ciphertext field for later
    delivery to the client (via the retrieval mechanism specified in
    section 3.2).

2.  After the ciphertext has been queued into persistent storage,
    the Provider MUST generate the ack's payload, concatenate with
    the received SURB-ACK header and transmit a SURB-ACK, iff the
    `BlockSphinxPlaintext`'s flags is equal to `1`, and a valid
    SURB is present in the payload.

The SURB-ACK payload MUST be completely zero filled (contain
only `0x00` bytes).

Providers MUST NOT generate and transmit a SURB-ACK unless the
ciphertext has been successfully queued for delivery.

Iff the Sphinx packet has a `surb_reply` command in the per-hop
command vector, then the entire Sphinx packet payload, along
with the `surb_id` value from the `surb_reply` command is queued
for later delivery to the client.

### 4.2 Client Receive Message Behavior

Clients periodically poll their Provider with a retreive_message
command. This section describes the client behavior upon receiving
messages from their Provider, based on type.

### 4.2.1 Client Message Processing

When a client receives an inbound message from their provider, denoted
as such by virtue of not being a SURB payload, the ciphertext will
contain a BlockCiphertext, that is first decrypted as per the Noise
protocol using the private component of their long term X25519 keypair,
into a Block.

It is then each client's responsibility to:

-   Queue, and reassemble multi-block messages as necessary based on the
    BlockCiphertext [s]{.title-ref} field (sender\'s long term public
    key), and the `message_id`, `total_blocks`, and `block_id` fields in
    the Block structure.

    When reassembling messages, the values of `s`, `message_id`, and
    `total_blocks` are fixed for any given distinct message. All
    differences in those fields across Blocks MUST be interpreted as the
    Blocks belonging to different messages.

    It is important to keep in mind that both the message and ACK
    delivery mechanisms are fundamentally unreliable, and that it is
    possible to receive blocks containing identical payload in the event
    of a spurious transmission. Clients MUST validate that such Blocks
    (overlapping `block_id`) are in fact spurious retransmissions by
    doing a bitwise compare of the block payloads, and take appropriate
    action such as warning the user if an anomaly is detected.

-   Present the IMF format message to the user.

    Clients MUST discard messages that fail to authenticate or decrypt,
    and MUST warn the user at a minimum, if the long term public key
    used by the sender to encrypt messages is different from a
    previously known value.

    Clients MAY impose a reasonable deadline for the reassembly process,
    after which partially received messages are discarded.

*NOTE: ya: Should we mandate that clients insert something like:
`[X-Katzenpost-Sender: <Base64(s)>]` as a header?*

## 5. Sphinx Packet Composition Considerations

Here we describe important facets of how clients construct Sphinx
packets. This section assumes the client interacts with the mix network
PKI as well as a universal time facility, the constraints of which have
been specified in detail in our PKI specification
[KATZMIXPKI](#KATZMIXPKI){.citation}.

### 5.1 Choosing Delays: for single Block messages and for multi Block messages

The Client generates a delay for the ingress provider and for each of
the mixes in the route, though not for the egress provider. The delays
for each mix hop are drawn from the exponential distribution
independently for each node. For a class of traffic `TRAFFIC_X`, the
parameter `LAMBDA_X` (also known as μ in the Loopix paper), which is the
inverse of the mean of the exponential distribution in milliseconds, is
published by the mix network PKI and the same for all clients. Given
`LAMBDA_X`, the sender just draws a random value from Exp(μ). The
frequency of sending messages weather they be forward messages or decoy
drops, is controlled by the parameter known as LAMBDA_P (aka λ_P) in the
loopix paper [LOOPIX](#LOOPIX){.citation}, which is the inverse of
the mean of the exponential distribution in milliseconds.

*NOTE: ya: Shouldn't this be up to the client? The sender\'s provider
delays the way this is speced out now... Design required here I think.*

For multi-Block messages, the client trickles the Blocks rather than
sending them all in a burst. This mitigates e2e correlation attacks that
look at bursts of multiple sent/received packets, and use that
information to link the sender and receiver of a multi-Block message.

## 5.2 Path selection algorithm

The path selection algorithm is composed of four steps:

1. Sample all forward and SURB delays.
2. Ensure total delays doesn't exceed `(time_till next_epoch) + 2 * epoch_duration`, as keys are only published 3 epochs in advance.
3. Pick forward and SURB mixes (Section 5.2.1).
4. Ensure that the forward and SURB mixes have a published key that will allow them to decrypt the packet at the time of it's expected arrival.

If either step 2 or 4 fails due to lack of keying, or excessive delay,
the entire path selection process MUST be restarted from the beginning.

### 5.2.1 Other Path Selection Considerations

The route contains the ingress and egress providers and a sequence of
randomly selected mixes. The sequence of mixes is chosen independently
for each Block.

Katzenpost uses the Layered topology, thus the selected path MUST
contain one and only one mix per layer, and MUST traverse all layers.
Within a layer, the mix is selected with probability proportional to its
bandwidth/capacity. Thus, if a mix has a fraction `f` of the total
capacity of its layer, it will be selected with probability `f`.

## 6. E-mail Client Integration Considerations

The e-mail client is a distinct component from the mix network client
because we want to avoid having to heavily modify an e-mail client just
to get it to work with our mix network. Instead we outline an e-mail
integration strategy below. The main functionalities of a mix network
client are:

1. send a message,
2. download the encrypted messages stored by the egress provider,
3. decrypt the messages using the private key (or universal private key
   if the client do not have a key, or if the sender didn't know the
   client's key),
4. reassemble multi-Block messages.

### 6.1 Message Retrieval

A local POP service can act as the mix network client, and decrypt the
final layer of Sphinx packet encryption. The K9-Mail and other e-mail
clients will download plaintext e-mail from this service. In this way we
avoid having to make large code changes to existing e-mail clients.

### 6.2 Message Sending

A local SMTP proxy will perform the Sphinx encryption; the user's
e-mail client will send messages to this local proxy. This avoids having
to perform the Sphinx encryption natively in the e-mail client.

## 7. Client Integration Considerations

This section specifies additional design considerations other than the
core reliability protocol design.

### 7.1 Message Retrieval

The mix network client component can utilize any of the above mentioned
reliability protocol and therefore can receive:

- a single Block message
- a multi-Block message

### 7.2 Information available to clients

Clients download Mix Descriptors from the PKI, also known as the Mix
Directory Authority service. More details about the PKI system and the
Mix Descriptors can be found in the Katzenpost Mix Network PKI
Specification.

Clients will have the following information available to them:

- Katzenpost Mix Network Parameters via the PKI:
    - topology information,
    - packet sizes for different classes of traffic,
    - parameter of the exponential delay (lambda) for Poisson mix
      strategy [KESDOGAN98](#KESDOGAN98){.citation},
      [LOOPIX](#LOOPIX){.citation}
    - the list of public keys and addresses of the providers,
    - the list of public keys and addresses of the active mixes,
- Mix Network Consensus Document containing Mix Descriptors as described in the Katzenpost Mix Network PKI Specification
- Current mix network time via Rough Time protocol with mixes

## 8. Anonymity Considerations

- The reliability protocol will allow for active confirmation attacks.
  [CYA2013](#CYA2013){.citation} ARQ protocol schemes present
  predictable user behavior such as message retransmissions when an
  ACK is not received in time. A malicious Provider who can also block
  or delay messages destined to other Providers can get confirmation
  that a message did NOT originate from one or more Providers. That
  is, if a retransmission is received while one of the Providers was
  blocked, it is highly likely this is because the client who is
  sending the message originates from that blocked Provider. If the
  client sends enough new messages then the adversary can eventually
  perform a binary search or tree search to determine the originating
  Provider.
- Between two communicating parties at least one Provider must be
  honest to maintain send/receiver anonymity with respect to third
  party observers.
- Usage of SURBs for message ACKs present deanonymization
  vulnerability via compulsion attacks. Each SURB contains a Sphinx
  packet header which contains routing information which is encrypted
  with several mix public key. An adversary could compel each of these
  mix operators to decrypt their portion of the Sphinx header until
  the entire route in traced to it's destination. Future work may
  build some partial defences for these attacks.
  [COMPULS05](#COMPULS05){.citation}
- There is no specified defence against n-1 attacks
  [TRICKLE02](#TRICKLE02){.citation} at this time. In future
  versions we may utilize heartbeat traffic to detect such attacks.
  [HEARTBEAT03](#HEARTBEAT03){.citation} However these denial of
  service attacks are not distinguishable from packet loss due to
  other causes such as network congestion. In the case of congestion
  it would be highly suboptimal to make the network congestion worse
  by sending lots of decoy traffic.
- This Provider based addressing scheme as described in
  [LOOPIX](#LOOPIX){.citation} is flexible enough to allow for
  alternate message system designs with different anonymity and
  security properties. In particular it should be possible to achieve
  strong location hiding properties.

## 9. Security Considerations

Client endpoint public keys must be distributed in order to maintain confidentiality and integrity.

## 10. Future Work and Research

- specify special features and design related to near real-time chat
  applications using a mix network transport protocol
- change the path selection algorithm to use legal jurisdictional
  region awareness for increasing the cost of compulsion attacks.
- change path selection to use a reputation system to defend against
  n-1 attacks and to increate network reliability;
  [MIRANDA](#MIRANDA){.citation} and
  [MIXRELIABLE](#MIXRELIABLE){.citation}
- Mitigate known active confirmation attacks?
- End to End Forward Secrecy using the Signal Double Ratchet
- make bulk transfers go faster using Selective Repeat ARQ and
  Go-Back-N ARQ
- make bulk transfers go faster using forward error correction
- make bulk transfers go faster using an alternate communications
  channel such as Tor-loops or similar decoy traffic protocol that
  uses Tor.

## Appendix A. References

### Appendix A.1 Normative References

### Appendix A.2 Informative References

## Appendix B. Citing This Document

### Appendix B.1 Bibtex Entry

Note that the following bibtex entry is in the IEEEtran bibtex style as
described in a document called "How to Use the IEEEtran BIBTEX Style".

```
@online{KatzEndToEnd,
title = {Katzenpost Mix Network End-to-end Protocol Specification},
author = {Yawning Angel and George Danezis and Claudia Diaz and Ania Piotrowska and David Stainton},
url = {https://github.com/katzenpost/katzenpost/blob/main/docs/specs/old/end_to_end.rst},
year = {2017}
}
```

[COMPULS05]{#COMPULS05 .citation-label}
Danezis, G., Clulow, J.,
"Compulsion Resistant Anonymous Communications",
Proceedings of Information Hiding Workshop,
June 2005,
https://www.freehaven.net/anonbib/cache/ih05-danezisclulow.pdf>\>.

[CONGAVOID]{#CONGAVOID .citation-label}
Jacobson, V., Karels, M.,
"Congestion Avoidance and Control",
Symposium proceedings on Communications architectures and protocols,
November 1988,
http://ee.lbl.gov/papers/congavoid.pdf

[CYA2013]{#CYA2013 .citation-label}
Geddes, J., Schuchard, M., Hopper, N.,
"Cover Your ACKs: Pitfalls of CovertChannel Censorship Circumvention",
https://www-users.cs.umn.edu/~hopper/ccs13-cya.pdf

[HEARTBEAT03]{#HEARTBEAT03 .citation-label}
Danezis, G., Sassaman, L.,
"Heartbeat Traffic to Counter (n-1) Attacks",
Proceedings of the Workshop on Privacy in the Electronic Society,
October 2003,
https://www.freehaven.net/anonbib/cache/danezis:wpes2003.pdf

[KATZMIXNET]{#KATZMIXNET .citation-label}
Angel, Y., Danezis, G., Diaz, C., Piotrowska, A., Stainton, D.,
"Katzenpost Mix Network Specification",
June 2017,
https://github.com/katzenpost/katzenpost/blob/main/docs/specs/mixnet.md

[KATZMIXPKI]{#KATZMIXPKI .citation-label}
Angel, Y., Piotrowska, A., Stainton, D.,
"Katzenpost Mix Network Public Key Infrastructure Specification",
December 2017,
https://github.com/katzenpost/katzenpost/blob/main/docs/specs/pki.md

[KATZMIXWIRE]{#KATZMIXWIRE .citation-label}
Angel, Y.
"Katzenpost Mix Network Wire Protocol Specification",
June 2017,
https://github.com/katzenpost/katzenpost/blob/main/docs/specs/wire-protocol.md

[KESDOGAN98]{#KESDOGAN98 .citation-label}
Kesdogan, D., Egner, J., and Büschkes, R.,
"Stop-and-Go-MIXes Providing Probabilistic Anonymity in an Open System."
Information Hiding,
1998.

[LOOPIX]{#LOOPIX .citation-label}
Piotrowska, A., Hayes, J., Elahi, T., Meiser, S., Danezis, G.,
"The Loopix Anonymity System",
USENIX,
August, 2017
https://arxiv.org/pdf/1703.00536.pdf

[MIRANDA]{#MIRANDA .citation-label}
Leibowitz, H., Piotrowska, A., Danezis, G., Herzberg, A.,
"No right to ramain silent: Isolating Malicious Mixes"
2017,
https://eprint.iacr.org/2017/1000.pdf

[MIXRELIABLE]{#MIXRELIABLE .citation-label}
Dingledine, R., Freedman, M., Hopwood, D., Molnar, D.,
"A Reputation System to Increase MIX-Net Reliability",
In Information Hiding, 4th International Workshop,
2001
https://www.freehaven.net/anonbib/cache/mix-acc.pdf

[NOISE]{#NOISE .citation-label}
Perrin, T.,
"The Noise Protocol Framework",
May 2017,
https://noiseprotocol.org/noise.pdf

[RFC2119]{#RFC2119 .citation-label}
Bradner, S.,
"Key words for use in RFCs to Indicate Requirement Levels",
BCP 14, RFC 2119, DOI 10.17487/RFC2119,
March 1997,
http://www.rfc-editor.org/info/rfc2119

[RFC5246]{#RFC5246 .citation-label}
Dierks, T. and E. Rescorla,
"The Transport Layer Security (TLS) Protocol Version 1.2",
RFC 5246, DOI 10.17487/RFC5246,
August 2008,
http://www.rfc-editor.org/info/rfc5246

[RFC5322]{#RFC5322 .citation-label}
Resnick, P., Ed.,
"Internet Message Format",
RFC 5322, DOI 10.17487/RFC5322,
October 2008,
https://www.rfc-editor.org/info/rfc5322

[RFC896]{#RFC896 .citation-label}
Nagle, J.,
"Congestion Control in IP/TCP Internetworks",
January 1984,
https://tools.ietf.org/html/rfc896

[SMODELS]{#SMODELS .citation-label}
Kelly, F.,
"Stochastic Models of Computer Communication Systems",
Journal of the Royal Statistical Society,
1985,
http://www.yaroslavvb.com/papers/notes/kelly-stochastic.pdf

[SPHINX]{#SPHINX .citation-label}
Danezis, G., Goldberg, I.,
"Sphinx: A Compact and Provably Secure Mix Format",
DOI 10.1109/SP.2009.15,
May 2009,
https://cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf

[SPHINXSPEC]{#SPHINXSPEC .citation-label}
Angel, Y., Danezis, G., Diaz, C., Piotrowska, A., Stainton, D.,
"Sphinx Mix Network Cryptographic Packet Format Specification"
July 2017,
https://github.com/katzenpost/katzenpost/blob/main/docs/specs/sphinx.md

[TRICKLE02]{#TRICKLE02 .citation-label}
Serjantov, A., Dingledine, R., Syverson, P.,
"From a Trickle to a Flood: Active Attacks on Several Mix Types",
Proceedings of Information Hiding Workshop,
October 2002,
https://www.freehaven.net/anonbib/cache/trickle02.pdf
