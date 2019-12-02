Katzenpost Mix Network Specification
************************************

| Yawning Angel
| George Danezis
| Claudia Diaz
| Ania Piotrowska
| David Stainton

| Version 0

.. rubric:: Abstract

This document describes the high level architecture and detailed
protocols and behavior required of mix nodes participating in the
Katzenpost Mix Network.

.. contents:: :local:

1. Introduction
===============

This specification provides the design of a mix network meant
to provide an anonymous messaging service.
Various system components such as client software, end to end
reliability protocol, Sphinx cryptographic packet format and wire
protocol are described in their own specification documents.

1.1 Terminology
----------------

* A ``KiB`` is defined as 1024 8 bit octets.

* ``Mix`` - A server that provides anonymity to clients. This is
  accomplished by accepting layer-encrypted packets from a
  Provider or another Mix, decrypting a layer of the
  encryption, delaying the packet, and transmitting
  the packet to another Mix or Provider.

* ``Mixnet`` - A network of mixes.

* ``Provider`` - A service operated by a third party that Clients
  communicate directly with to communicate with the Mixnet.
  It is responsible for Client authentication,
  forwarding outgoing messages to the Mixnet, and storing incoming
  messages for the Client. The Provider MUST have the ability to
  perform cryptographic operations on the relayed packets.

* ``Node`` - A Mix or Provider instance.

* ``User`` - An agent using the Katzenpost system.

* ``Client`` - Software run by the User on its local device to
  participate in the Mixnet.

* ``Katzenpost`` - A project to design an improved mix service as described
  in this specification. Also, the name of the reference
  software to implement this service, currently under
  development.

  Classes of traffic - We distinguish the following classes of traffic:

  * ACKs (denoted by the surb_reply Sphinx routing command in the last hop)
  * Forward messages

  .. note::

     This may be changed after we do our analysis on the stats

* ``Packet`` - A string transmitted anonymously thought the Katzenpost network.
  The length of the packet is fixed for every class of traffic.

* ``Payload`` - The [xxx] KiB portion of a Packet containing a message,
  or part of a message, to be delivered anonymously.

  .. note::

     This has to be rephrased after the analysis of the stats.

* ``Message`` - A variable-length sequence of octets sent anonymously
  through the network. Short messages are sent in a single
  packet; long messages are fragmented across multiple
  packets (see the Katzenpost Mix Network End-to-end
  Protocol Specification for more information about
  encoding messages into payloads). 

  .. note:: 

     This has to be rephrased after
     The analysis of the stats; if we have multiple classes of traffic

* ``MSL`` - Maximum Segment Lifetime, 120 seconds.

1.2 Conventions Used in This Document
-------------------------------------

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [RFC2119]_.

2. System Overview
==================

The presented system design is based on [LOOPIX]_. The detailed
End-to-end specification, describing the operations performed
by the sender and recipient, as well sender’s Provider and
recipient’s Provider, are presented in [KATZMIXE2E]_.
Below, we present the system overview.

The Provider ran by each service provider is responsible for
accepting packets from the client, and forwarding them
to the mix network, which then relays packets to the recipient's
Provider. Upon receiving a packet from the mix network, the Provider
is responsible for signaling that the packet was received by sending
an acknowledgment, as well as storing the packet until it is retrieved
by the recipient.
::

      +--------+     +----------+     +-------------+
      | Client | <-> |          |     |             |
      +--------+     |          |     |             |
                     | Provider | <-> |             |
      +--------+     |          |     | Mix Network |
      | Client | <-> |          |     |             |
      +--------+     +----------+     |             |
                                      |             |
      +--------+     +----------+     |             |
      | Client | <-> | Provider | <-> |             |
      +--------+     +----------+     +-------------+

Not shown in the diagram is the PKI system that handles the
distribution of various network wide parameters, and information
required for each participant to participate in the network such as
IP address/port combinations that each node can be reached at, and
cryptographic public keys. The specification for the PKI is beyond
the scope of this document and is instead covered in [KATZMIXPKI]_.

The Provider and Client behavior is specified in [KATZMIXE2E]_,
though certain aspects of the Provider behavior are also specified
here, as Providers are Nodes.

The mix network provides neither reliable nor in-order delivery
semantics. It is up to the applications that make use of the mix
network to implement additional mechanism if either property is
desired.


2.1 Threat Model
-----------------

We assume that the sender and recipient do know each other's
addresses. This system guarantees third-party anonymity, meaning
that no parties other than sender and recipient are able to learn
that the sender and recipient are communicating. Note that this is
in contrast with other designs, such as Mixminion, which provide
sender anonymity towards recipients as well as anonymous replies.

Additionally as all of a given client's messages go through a
single provider instance, it is assumed that in the absence of
any specific additional defenses, that the Provider can determine
the approximate mail volume originating from and destined to a
given client. We consider the provider follows the protocol
and might be an honest-but-curious adversary.

External local network observers can determine the number of
Packets traversing their region of the network because at this
time no decoy traffic has been specified. Global observers will
not be able to de-anonymize packet paths if there are enough
packets traversing the mix network.

A malicious mix only has the ability to remember which input
packets correspond to the output packets. To discover the
entire path all of the mixes in the path would have to be
malicious. Moreover, the malicious mixes can drop, inject, modify
or delay the packets for more or less time than specified.

2.2 Network Topology
---------------------

The Katzenpost Mix Network uses a layered topology consisting of a
fixed number of layers, each containing a set of mixes. At any
given time each Mix MUST only be assigned to one specific layer.
Each Mix in a given layer N is connected to every other Mix in
the previous and next layer, and or every participating Provider
in the case of the mixes in layer 0 or layer N (first and last layer).
::

                             Layer 0        Layer 1        Layer 2
          +----------+      +-------+      +-------+      +-------+
      +-> | Provider | -+-> |  Mix  | -+-> |  Mix  | -+-> |  Mix  | -+
      |   +----------+  |   +-------+  |   +-------+  |   +-------+  |
      |                 |              |              |              |
      |   +----------+  |   +-------+  |   +-------+  |   +-------+  |
      +-> | Provider | -+-> |  Mix  | -+-> |  Mix  | -+-> |  Mix  | -+
      |   +----------+  |   +-------+  |   +-------+  |   +-------+  |
      |                 |              |              |              |
      |                 |   +-------+  |   +-------+  |   +-------+  |
      |                 +-> |  Mix  | -+-> |  Mix  | -+-> |  Mix  | -+
      |                     +-------+      +-------+      +-------+  |
      |                                                              |
      +--------------------------------------------------------------+

         Note: Multiple distinct connections are collapsed in the
         figure for sake of brevity/clarity.

The network topology MUST also maximize the number of security
domains traversed by the packets. This can be achieved by not
allowing mixes from the same security domain to be in different layers.

Requirements for the topology:

* Should allow for non-uniform throughput
  of each mix (Get bandwidth weights from the PKI).
* Should maximize distribution among security domains,
  in this case the mix descriptor specified family field
  would indicate the security domain or entity operating the mix.
* Other legal jurisdictional region awareness for increasing
  the cost of compulsion attacks.

3. Packet Format Overview
=========================

For the packet format of the transported messages we use the Sphinx
cryptographic packet format. The detailed description of the
packet format, construction, processing and security/anonymity
considerations see [SPHINXSPEC]_, "The Sphinx Mix Network
Cryptographic Packet Format Specification".

As the Sphinx packet format is generic, the Katzenpost Mix Network
must provide a concrete instantiation of the format, as well as
additional Sphinx per-hop routing information commands.

3.1 Sphinx Cryptographic Primitives
-----------------------------------

For the current version of the Katzenpost Mix Network, let the
following cryptographic primitives be used as described in the
Sphinx specification.

* ``H(M)`` - As the output of this primitive is only used locally to
  a Mix, any suitable primitive may be used.

* ``MAC(K, M)`` - HMAC-SHA256-128 [RFC6234]_, M_KEY_LENGTH of 32 bytes
  (256 bits), and MAC_LENGTH of 16 bytes (128 bits).

* ``KDF(SALT, IKM)`` - HKDF-SHA256, HKDF-Expand only, with SALT used
  as the info parameter.

* ``S(K, IV)``  - CTR-AES128 [SP80038A]_, S_KEY_LENGTH of 16 bytes
  (128 bits), and S_IV_LENGTH of 12 bytes (96 bits),
  using a 32 bit counter.

* ``SPRP_Encrypt(K, M)/SPRP_Decrypt(K, M)`` - AEZv5 [AEZV5]_,
  SPRP_KEY_LENGTH of 48 bytes (384 bits). As there is a
  disconnect between AEZv5 as specified and the Sphinx
  usage, let the following be the AEZv5 parameters:

  * nonce - 16 bytes, reusing the per-hop Sphinx header IV.
  * additional_data - Unused.
  * tau - 0 bytes.

* ``EXP(X, Y)`` - X25519 [RFC7748]_ scalar multiply, GROUP_ELEMENT_LENGTH
  of 32 bytes (256 bits), G is the X25519 base point.

3.2 Sphinx Packet Parameters
----------------------------

The following parameters are used as for the Katzenpost Mix Network
instantiation of the Sphinx Packet Format:

* ``AD_SIZE``            - 2 bytes.

* ``SECURITY_PARAMETER`` - 16 bytes.

* ``PER_HOP_RI_SIZE``    - (XXX/ya: Addition is hard, let's go shopping.)

* ``NODE_ID_SIZE``       - 32 bytes, the size of the Ed25519 public key,
  used as Node identifiers.

* ``RECIPIENT_ID_SIZE``  - 64 bytes, the maximum size of local-part
  component in an e-mail address.

* ``SURB_ID_SIZE``       - Single Use Reply Block ID size, 16 bytes.

* ``MAX_HOPS``           - 5, the ingress provider, a set of three mixes,
  and the egress provider.

* ``PAYLOAD_SIZE``       - (XXX/ya: Subtraction is hard, let's go shopping.)

* ``KDF_INFO``           - The byte string 'Katzenpost-kdf-v0-hkdf-sha256'.

The Sphinx Packet Header ``additional_data`` field is specified as follows::

      struct {
          uint8_t version;  /* 0x00 */
          uint8_t reserved; /* 0x00 */
      } KatzenpostAdditionalData;
      
.. note::

     Double check to ensure that this causes the rest of the packet
     header to be 4 byte aligned, when wrapped in the wire protocol command
     and framing. This might need to have 3 bytes reserved instead.

All nodes MUST reject Sphinx Packets that have ``additional_data`` that
is not as specified in the header.

.. note::

   Design decision.

   * We can eliminate a trial decryption step per packet around the
     epoch transitions by having a command that rewrites the AD on
     a per-hop basis and including an epoch identifier.

     I am uncertain as to if the additional complexity is worth it
     for a situation that can happen for 4 mins out of every 3 hours.

3.3 Sphinx Per-hop Routing Information Extensions
-------------------------------------------------

The following extensions are added to the Sphinx Per-Hop Routing
Information commands.

Let the following additional routing commands be defined in the
extension RoutingCommandType range (0x80 - 0xff)::

      enum {
          mix_delay(0x80),
      } KatzenpostCommandType;

The mix_delay command structure is as follows::

      struct {
          uint32_t delay_ms;
      } NodeDelayCommand;

4. Mix Node Operation
=====================

All Mixes behave in the following manner:

* Accept incoming connections from peers, and open persistent
  connections to peers as needed (:ref:`Section 4.1 <4.1>`).

* Periodically interact with the PKI to publish Identity and
  Sphinx packet public keys, and to obtain information about
  the peers it should be communicating with, along with
  periodically rotating the Sphinx packet keys for forward
  secrecy (:ref:`Section 4.2 <4.2>`).

* Process inbound Sphinx Packets, delay them for the specified time
  and forward them to the appropriate Mix and or Provider (:ref:`Section 4.3 <4.3>`).

All Nodes are identified by their link protocol signing key, for
the purpose of the Sphinx packet source routing hop identifier.

All Nodes participating in the Mix Network MUST share a common
view of time, via NTP or similar time synchronization mechanism.

.. _4.1:

4.1 Link Layer Connection Management
------------------------------------

All communication to and from participants in the Katzenpost Mix
Network is done via the Katzenpost Mix Network Wire Protocol [KATZMIXWIRE]_.

Nodes are responsible for establishing the connection to the next
hop, for example, a mix in layer 0 will accept inbound connections
from all Providers listed in the PKI, and will proactively establish
connections to each mix in layer 1.

Nodes MAY accept inbound connections from unknown Nodes, but MUST
not relay any traffic until they became known via listing in the
PKI document, and MUST terminate the connection immediately if
authentication fails for any other reason.

Nodes MUST impose an exponential backoff when reconnecting if a
link layer connection gets terminated, and the minimum retry
interval MUST be no shorter than 5 seconds.

Nodes MAY rate limit inbound connections as required to keep load
and or resource use at a manageable level, but MUST be prepared to
handle at least one persistent long lived connection per
potentially eligible peer at all times.

.. _4.2:

4.2 Sphinx Mix and Provider Key Rotation
----------------------------------------

Each Node MUST rotate the key pair used for Sphinx packet processing
periodically for forward secrecy reasons and to keep the list of seen
packet tags short. The Katzenpost Mix Network uses a fixed interval
(``epoch``), so that key rotations happen simultaneously throughout
the network, at predictable times.

Let each epoch be exactly ``10800 seconds (3 hours)`` in duration, and
the 0th Epoch begin at ``2017-06-01 00:00 UTC``. For more details see
our "Katzenpost Mix Network Public Key Infrastructure Specification"
document. [KATZMIXPKI]_

.. _4.3:

4.3 Sphinx Packet Processing
----------------------------

The detailed processing of the Sphinx packet is described in the
Sphinx specification: "The Sphinx Mix Network Cryptographic Packet
Format Specification”. Below, we present an overview of the steps
which the node is performing upon receiving the packet:

1. Records the time of reception.

2. Perform a ``Sphinx_Unwrap`` operation to authenticate and
   decrypt a packet, discarding it immediately if the operation
   fails.

3. Apply replay detection to the packet, discarding replayed
   packets immediately.

4. Act on the routing commands.

   All packets processed by Mixes MUST contain the following
   commands.

   * ``NextNodeHopCommand``, specifying the next Mix or Provider
     that the packet will be forwarded to.

   * ``NodeDelayCommand``, specifying the delay in milliseconds to
     be applied to the packet, prior to forwarding it to the
     Node specified by the NextNodeHopCommand, as measured from
     the time of reception.

     Mixes MUST discard packets that have any commands other
     than a ``NextNodeHopCommand`` or a ``NodeDelayCommand``. Note that
     this does not apply to Providers or Clients, which have
     additional commands related to recipient and :abbr:`SURB (Single Use Reply Block)` processing.

Nodes MUST continue to accept the previous epoch's key for up
to 1MSL past the epoch transition, to tolerate latency and clock
skew, and MUST start accepting the next epoch's key 1*MSL prior
to the epoch transition where it becomes the current active key.

Upon the final expiration of a key (1MSL past the epoch
transition), Nodes MUST securely destroy the private component
of the expired Sphinx packet processing key along with the backing
store used to maintain replay information associated with the
expired key.

Nodes MAY discard packets at any time, for example to keep
congestion and or load at a manageable level, however assuming
the ``Sphinx_Unwrap`` operation was successful, the packet MUST be
fed into the replay detection mechanism.

Nodes MUST ensure that the time a packet is forwarded to the next Node
is around the time of reception plus the delay specified in ``NodeDelayCommand``.
Since exact millisecond processing is unpractical, implementations MAY tolerate
a small window around that time for packets to be forwarded.
That tolerance window SHOULD be kept minimal.

Nodes MUST discard packets that have been delayed
for significantly more time than specified by the ``NodeDelayCommand``.

5. Anonymity Considerations
===========================

5.1 Topology
------------

Layered topology is used because it offers the best level of
anonymity and ease of analysis, while being flexible enough to
scale up traffic. Whereas most mixnet papers discuss their security
properties in the context of a cascade topology, which does not
scale well, or a free-route network, which quickly becomes
intractable to analyze when the network grows, while providing
slightly worse anonymity than a layered topology. [MIXTOPO10]_

Important considerations when assigning mixes to layers, in order
of decreasing importance, are:

1. Security: do not allow mixes from one security domain to be
   in different layers to maximise the number of security
   domains traversed by a packet

2. Performance: arrange mixes in layers to maximise the capacity
   of the layer with the lowest capacity (the bottleneck layer)

3. Security: arrange mixes in layers to maximise the number of
   jurisdictions traversed by a packet (this is harder to do
   really well than it seems, requires understanding of legal
   agreements such as MLATs).

5.2 Mixing strategy
-------------------

As a mixing technique the Poisson mix strategy [LOOPIX]_
[KESDOGAN98]_ is used, which REQUIRES that a packet at each hop in
the route is delayed by some amount of time, randomly selected by
the sender from an exponential distribution. This strategy allows
to prevent the timing correlation of the incoming and outgoing
traffic from each node. Additionally, the parameters of the
distribution used for generating the delay can be tuned up and down
depending on the amount of traffic in the network and the application
for which the system is deployed.

6. Security Considerations
==========================

The source of all authority in the mixnet system comes from the
Directory Authority system which is also known as the mixnet PKI.
This system gives the mixes and clients a consistent view of the
network while allowing human intervention when needed. All public
mix key material and network connection information is distributed
by this Directory Authority system.

Appendix A. References
======================

Appendix A.1 Normative References
---------------------------------

.. [RFC2119]   Bradner, S., "Key words for use in RFCs to Indicate
               Requirement Levels", BCP 14, RFC 2119,
               DOI 10.17487/RFC2119, March 1997,
               <http://www.rfc-editor.org/info/rfc2119>.

.. [RFC5246]   Dierks, T. and E. Rescorla, "The Transport Layer Security
               (TLS) Protocol Version 1.2", RFC 5246,
               DOI 10.17487/RFC5246, August 2008,
               <https://www.rfc-editor.org/info/rfc5246>.

.. [RFC6234]   Eastlake 3rd, D. and T. Hansen, "US Secure Hash Algorithms
               (SHA and SHA-based HMAC and HKDF)", RFC 6234,
               DOI 10.17487/RFC6234, May 2011,
               <https://www.rfc-editor.org/info/rfc6234>.

.. [SP80038A]  Dworkin, M., "Recommendation for Block Cipher Modes
               of Operation",  SP800-38A,
               10.6028/NIST.SP.800, December 2001,
               <https://doi.org/10.6028/NIST.SP.800-38A>

.. [AEZV5]     Hoang, V., Krovetz, T., Rogaway, P., "AEZ v5:
               Authenticated Encryption by Enciphering", March 2017,
               <http://web.cs.ucdavis.edu/~rogaway/aez/aez.pdf>

.. [RFC7748]   Langley, A., Hamburg, M., and S. Turner, "Elliptic Curves
               for Security", RFC 7748, January 2016.

.. [KATZMIXWIRE] Angel, Y., "Katzenpost Mix Network Wire Protocol Specification", June 2017.
                 <https://github.com/katzenpost/docs/blob/master/specs/wire-protocol.rst>.

.. [KATZMIXE2E]  Angel, Y., Danezis, G., Diaz, C., Piotrowska, A., Stainton, D.,
                 "Katzenpost Mix Network End-to-end Protocol Specification", July 2017,
                 <https://github.com/katzenpost/docs/blob/master/specs/end_to_end.rst>.

.. [KATZMIXPKI]  Angel, Y., Piotrowska, A., Stainton, D.,
                 "Katzenpost Mix Network Public Key Infrastructure Specification", December 2017,
                 <https://github.com/katzenpost/docs/blob/master/specs/pki.rst>.

.. [SPHINXSPEC] Angel, Y., Danezis, G., Diaz, C., Piotrowska, A., Stainton, D.,
                "Sphinx Mix Network Cryptographic Packet Format Specification"
                July 2017, <https://github.com/katzenpost/docs/blob/master/specs/sphinx.rst>.

Appendix A.2 Informative References
-----------------------------------

.. [LOOPIX]    Piotrowska, A., Hayes, J., Elahi, T., Meiser, S., Danezis, G.,
               “The Loopix Anonymity System”,
               USENIX, August, 2017
               <https://arxiv.org/pdf/1703.00536.pdf>

.. [KESDOGAN98]   Kesdogan, D., Egner, J., and Büschkes, R.,
                  "Stop-and-Go-MIXes Providing Probabilistic Anonymity in an Open System."
                  Information Hiding, 1998,
                  <https://www.freehaven.net/anonbib/cache/stop-and-go.pdf>.

.. [MIXTOPO10]  Diaz, C., Murdoch, S., Troncoso, C., "Impact of Network Topology on Anonymity
                and Overhead in Low-Latency Anonymity Networks", PETS, July 2010,
                <https://www.esat.kuleuven.be/cosic/publications/article-1230.pdf>.

Appendix B. Citing This Document
================================

Appendix B.1 Bibtex Entry
-------------------------

Note that the following bibtex entry is in the IEEEtran bibtex style
as described in a document called "How to Use the IEEEtran BIBTEX Style".

::

   @online{KatzMixnet,
   title = {Katzenpost Mix Network Specification},
   author = {Yawning Angel and George Danezis and Claudia Diaz and Ania Piotrowska and David Stainton},
   url = {https://github.com/Katzenpost/docs/blob/master/specs/mixnet.rst},
   year = {2017}
   }
