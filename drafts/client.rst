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


4. Forward Messaging
====================

The client shall send forward messages in either of two modes:

* unreliable
* reliable


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


5. Service queries
==================


6. Cryptographic Persistent Storage
===================================


7. Anonymity Considerations
===========================


8. Security Considerations
==========================


9. Acknowledgements
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

Appendix A.2 Informative References
-----------------------------------

.. [LOOPIX]    Piotrowska, A., Hayes, J., Elahi, T., Meiser, S., Danezis, G.,
               “The Loopix Anonymity System”,
               USENIX, August, 2017
               <https://arxiv.org/pdf/1703.00536.pdf>.


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
