Katzenpost client library design specification
**********************************************

| David Stainton
| Masala

Version 0

.. rubric:: Abstract

This document describes the design of a client software library,
a minimal message oriented network transport protocol library.

.. contents:: :local:


1. Introduction
===============

This design document illuminates many complex mixnet client design
considerations that are not already covered by "Katzenpost Mix Network
End-to-end Protocol Specification" [KATZMIXE2E]_.  Moreover the
existing Katzenpost reference client, minclient can be found here:

* https://github.com/katzenpost/minclient

Minclient is very low level and in most cases should not be used
directly to compose mixnet client applications. In contrast we shall
herein describe the design of a client library which provides two
categories of message oriented bidirectional communication channels:

1. client to client
2. client to server

This library could be used to compose more sophisticated communication
channels which provide additional cryptographic security properties to
the client application such as:

* Forward secrecy
* Post-compromise security

We shall describe the design considerations for several variations of
mixnet communication protocols:

* unreliable location-hiding client to client
* reliable location-hiding client to client
* unreliable non-location-hiding client to client
* reliable non-location-hiding client to client
* unreliable client to server
* reliable client to server
* client to server publish-subscribe


1.1 Conventions Used in This Document
-------------------------------------

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [RFC2119]_.

1.2 Terminology
---------------

* ``ACK`` - A protocol acknowledgment message.

* ``ARQ`` - Automatic Repeat reQuest is an error correction method
  which requires two-way communication and incurs a delay penalty
  when used.


2. Protocol Overview
====================

Clients send forward messages and decoy loop messages. Loop decoy
messages are addressed to the sending client whereas forward messages
are destined for other clients or servers. An idle client sends just
as many messages as a busy client on average.

In contrast to [LOOPIX]_, clients make use of two Poisson processes:

* ``λP`` - Time interval between sending messages from the egress queue.
* ``λH`` - Delay choosen for each hop.

Clients receive messages to send from the application via an egress
queue. When λP triggers a send from the egress queue and it is empty
a decoy loop message is sent.

The use of automatic retransmissions for unacknowledged messages
adds additional complexities to the client. However unlike the
classical packet switching network literature we MUST NOT have
predictable retransmission intervals. This is in order to prevent active
confirmation attacks which can completely break the mixnet location
hiding properties.


3. Message Retreival
====================

There are two types of message retreival that are possible and
they are:

* retreival from local Provider, which means directly connecting
  to the Provider with our Katzenpost link layer wire protocol
  and sending the "retreive message" command to retreive messages
  from the message spool on that Provider for a given user
  identity.

* retreival from remote Provider: Here we are referring to the
  "Katzenpost Dead Drop Extension" [KATZDEADDROP]_ specification
  document which goes into detail how the remote Provider can be
  queried "over the mixnet".


4. Reliability
==============

Reliable messaging via our mixnet ARQ protocol scheme is used with
messages to clients and service queries [KAETZCHEN]_ as well.

4.1 Reliability
---------------

As stated in [KATZMIXE2E]_, our ARQ protocol scheme MUST obey the
following rules:

* All retransmitted blocks MUST be re-encrypted, and have a
  entirely new set of paths and delays. In simple terms, this
  means re-doing the packet creation/transmission from step 2
  for each retransmitted block.

* Senders MUST NOT retransmit blocks at a rate faster than one
  block per 3 seconds.

* Retransmissions must NOT have predictable timing otherwise
  it exposes the destination Provider to discovery by a
  powerful adversary that can perform active confirmation
  attacks.

* Senders MUST NOT attempt to retransmit blocks indefinitely,
  and instead give up on the entire message after it fails to
  arrive after a certain number of retransmissions.

Due to using the Poisson mix strategy the client knows the
approximate round trip time.


4.1.1 ARQ Implementation Considerations
---------------------------------------

When a SURB reply is received by a client, this means the client
receives a ciphertext payload and a SURB ID. This SURB ID tells our
ARQ statemachine which message is being acknowledged. The client uses
the SURB ID to determine which private key to use for decrypting the
ciphertext.

The two SURB reply cases are currently:

* SURB ACKnowledgments
* SURB replies from service queries

In the case of a SURB-ACK the payload plaintext should be all zero
bytes (0x00) whereas replies from service queries have no such
restriction.

A client's retransmission intervals MUST not be predictable or a
powerful active confirmation attack can be performed to discovered the
client's Provider. Furthermore, classical network literature states
that we must have an exponential backoff for retransmissions. [CONGAVOID]_
[SMODELS]_  [RFC896]_ Therefore clients MUST randomize retransmission
intervals with the lower bounds being set by the exponential curve
or a linear approximation of such.

In practice these two delays can be implemented using priority queues
where the priority is set to the future expiration time. Early
cancellations can be marked as such using a hashmap to avoid doing a
linear scan of the priority queue.


::

     .-------------.        .--------------.
     | Application |  --->  | egress queue | --->  The Mix Network
     `-------------'      _ `--------------'
                          /|     |
                       __/       |
                      /          V
                    _/        .----------------.
                   /          | retransmission |
                 _/           |      queue     |
                /            `----------------'
               |                    |
               \                    |
                \                   V
                 \            .------------.
                  \           | exp. delay |
                   '--------- |   queue    |
                              `------------'

* ``egress queue`` -
* ``retransmission queue`` -
* ``exp. delay queue`` -

X. Cryptographic Persistent Storage
===================================


X. Anonymity Considerations
===========================


X. Security Considerations
==========================


X. Acknowledgements
===================

This client design is inspired by “The Loopix Anonymity System”
[LOOPIX]_ and in particular the specific decoy traffic design comes
from conversations with Claudia Diaz and Ania Piotrowska.


Appendix A. References
======================

Appendix A.1 Normative References
---------------------------------

.. [RFC2119]   Bradner, S., "Key words for use in RFCs to Indicate
               Requirement Levels", BCP 14, RFC 2119,
               DOI 10.17487/RFC2119, March 1997,
               <http://www.rfc-editor.org/info/rfc2119>.

.. [KATZMIXNET]  Angel, Y., Danezis, G., Diaz, C., Piotrowska, A., Stainton, D.,
                "Katzenpost Mix Network Specification", June 2017,
                <https://github.com/Katzenpost/docs/blob/master/specs/mixnet.rst>.

.. [KATZMIXE2E]  Angel, Y., Danezis, G., Diaz, C., Piotrowska, A., Stainton, D.,
                 "Katzenpost Mix Network End-to-end Protocol Specification", July 2017,
                 <https://github.com/katzenpost/docs/blob/master/specs/end_to_end.rst>.

.. [KATZDEADDROP] Stainton, D., "Katzenpost Dead Drop Extension", February 2018,
                  <https://github.com/Katzenpost/docs/blob/master/drafts/deaddrop.rst>.

.. [KAETZCHEN]  Angel, Y., Kaneko, K., Stainton, D.,
                "Katzenpost Provider-side Autoresponder", January 2018,
                <https://github.com/Katzenpost/docs/blob/master/drafts/kaetzchen.rst>.

Appendix A.2 Informative References
-----------------------------------

.. [LOOPIX]    Piotrowska, A., Hayes, J., Elahi, T., Meiser, S., Danezis, G.,
               “The Loopix Anonymity System”,
               USENIX, August, 2017
               <https://arxiv.org/pdf/1703.00536.pdf>.

.. [CONGAVOID] Jacobson, V., Karels, M., "Congestion Avoidance and Control",
               Symposium proceedings on Communications architectures and protocols,
               November 1988, <http://ee.lbl.gov/papers/congavoid.pdf>.

.. [SMODELS]  Kelly, F., "Stochastic Models of Computer Communication Systems",
              Journal of the Royal Statistical Society, 1985,
              <http://www.yaroslavvb.com/papers/notes/kelly-stochastic.pdf>.

.. [RFC896]  Nagle, J., "Congestion Control in IP/TCP Internetworks",
             January 1984, <https://tools.ietf.org/html/rfc896>.


sloppy notes that masala wrote:
-------------------------------

Storage can persistence shall have multiple implementations:
    * cryptographic storage to disk
    * plaintext memory storage

Storage API for communications metadata.
 * Records state of messages and SURB IDs for service replies or
   message acknowledgements. Items persisted link a specific queries
   with their replies. In the case of reliable messages ... In the
   case of a service query

Information that is contained in the metadata storage consists of:
 * Message ID, SURB ID, status triples
 * Message indices?

Information that is NOT stored in the metadata storage and is up to
the consumer of the client API to implement:
  * Contents of messages
  * Contacts of clients
  * Anything implemented by the API consumer

Implementations
 * In memory implementation. Nothing is persisted to disk, and all
   state is lost at program exit. No reliability guarrantees exist
   after a client instance is terminated.
 * On disk implementation. Message metadata is retained to disk for
   <duration> or until a message is acknowledged or a response is
   received. Upon restarting a client this metadata repository is
   loaded from disk.
 
API methods (subject to change)
 * Create initializes a metadata store
 * Read loads a metadata store from disk
 * Write writes a metadata store to disk
 * Destroy erases a metadata store from disk

Each store item contains one CBOR serialized structure that is
deserialized into program memory at client initialization. At client
graceful shutdown, state is stored to disk by serializing the
in-memory structure and writing it to disk. The storage API does NOT
provide journaling or fault handling in the event of a program
crash. (Too bad, so sad?).
