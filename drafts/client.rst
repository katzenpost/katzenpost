Katzenpost Low-level client design specification
************************************************

| David Stainton
| Masala

Version 0

.. rubric:: Abstract

This document describes the design of a client software library,
a minimal message oriented network transport protocol library.

.. contents:: :local:


1. Introduction
===============

This client library allows developers to build any kind of message
oriented peer to peer distributed or decentralized system where it is
difficult for network observers to determine which clients are
exchanging messages. However we also wish to have traffic
indistinguishability for all the applications that use this library,
in terms of the timing, size of messages and messages sent versus
received. This means we can have many kinds of applications using the
mix network and it is difficult for a passive network observer to
determine which network application a given user is using.

Since mix networks are fundamentally a lossy packet switching network,
we MUST optional provide reliability. In this case and in accordance
with the End to End Design Principle, we implement a custome Automatic
Repeat reQuest error correction protocol scheme which provides
reliability but not in order delivery.

The scope of this client will not include any end to end cryptography
with the exception of the Sphinx packet format. However, Sphinx packets
in Katzenpost terminate at the destination Provider. Therefore the data
being transported MUST use some form of encryption. This presents several
challenges that are not solved in this library.

This library SHOULD be used to compose more sophisticated client libraries.
These are general purpose message oriented network transport protocol libraries
that are intended to be used with both end to end communication clients,
peer to peer systems and other forms of decentralized and distributed
communication systems where traffic analysis resistance is required.

1.1 Conventions Used in This Document
-------------------------------------

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [RFC2119]_.

1.2 Terminology
---------------

2. Protocol Overview
====================

Unlike Loopix, this client shall use only one decoy traffic type,
loops. As described in the paper, client loops are destined for the
originating client. However in Katzenpost the mechanism of the loop is
different than the Loopix paper. In Katzenpost we make use of the
"loop" service which is running on one or more Providers. The forward
message which is destined for the loop service contains a SURB which
the loop service uses to send a reply that closes the loop.

An idle client sends just as many messages as a busy client. Client
timing is achieved by putting outbound messages into a FIFO queue
where the scheduler uses a Poisson process to determine time duration
between removing messages from the queue for sending over the mixnet.
We denote this Poisson process as λP whereas the delay choosen for
each hop shall be known as λH. As is desbribed in the Loopix paper,
when the egress FIFO queue is empty, decoy loop messages are sent.

All messages sent are bundled with a SURB in the Sphinx packet payload
so that a reply can be sent by the destination Provider. This is done
so that reliable and unreliable messages are indistinguishable from
our decoy loop traffic.

Unlike TCP, our ARQ scheme doesn't need to make round trip time
estimates because we use the Poisson mix strategy where clients
compose Sphinx packets with a "delay" Sphinx routing command for each
hop. Each mix in turn delays the Sphinx packet for the specified
duration in the delay command that it decrypted.

In order to avoid active confirmation attacks, the ARQ scheme MUST use
a random delay for retransmission durations. However it should be
noted that this retransmission duration MUST be bounded by a linear
approximation of an exponential curve to avoid congestion collapse. I
suggest using a descrete network event simulator for tuning to lower
probability of congestion collapse for a given network utilization AND
also for discovering upper bounds on reliable network utilization with
minimal performance degradation. In other words, we need to use real
network engineering and not assume the academic mix network
abstraction is sufficient for understanding emergent properties.

We specify an optional ARQ scheme with a fixed window size for all
clients, uses one ACK per message. Since this is an optional ARQ
scheme, a higher level client would be able to possibly implement a
more efficient ARQ scheme for use with a fragmentation scheme. Hybrid
FEC + ARQ schemes are unlikely to yield much benefit without a context
where tuning the FEC can be done with some accuracy. In other words,
save the FEC usage for radio networks, whereas Internet overlay
networks cannot predict transport dataloss like a radio network can.

3. Message Retreival
====================

There are two types of message retreival that are possible and
they are:

    * retreival from local Provider, which means directly connecting
      to the Provider with our Katzenpost link layer wire protocol
      and sending the "retreive message" command to retreive messages
      from the message spool on that Provider for a given user
      identity.

    * retreival from remote Provider: Here we shall refer to the
      "dead drop" specification document which goes into detail how
      the remote Provider can be queried "over the mixnet".


4. Forward Messaging
====================

The client shall send forward messages in either of two modes:

    * reliable
    * unreliable

The reliable mode means the forward message is bundled with a SURB in
the Sphinx payload and this SURB is used by the destination Provider
to send an ACK control message back the originating client.


3.1 Reliable Message delivery
-----------------------------

Message retransmission occurs after a timeout determined by the
estimated forward+return path delays and (exponential back off?).
Message retransmissions occur N times before a permanent error is
returned to the originating client (how?)

3.2 Unreliable Message delivery
-------------------------------

Messages sent via the unreliable path are sent once with no
guarrantees about reliability or indication if they have been
delivered. No SURBs are exposed to the recipients provider.


5. Service queries
==================


6. Cryptographic Persistent Storage
===================================

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


7. Anonymity Considerations
===========================


8. Security Considerations
==========================


Appendix A. References
======================

Appendix A.1 Normative References
---------------------------------

Appendix A.2 Informative References
-----------------------------------
