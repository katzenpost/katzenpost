Katzenpost Zcash Send Protocol Specification
********************************************

| David Stainton

Version 0


.. rubric:: Abstract

This document describes the zcash transaction submission
Kaetzchen service [KAETZCHEN] which allows clients of the
mix network to anonymously write transactions to the Zcash
blockchain. This is an unreliable unidirectional protocol
from client to Zcash blockchain.

.. contents:: :local:


1. Introduction
===============

The primary use case for this protocol is to facilitate Zcash wallet
developers designing for the highest degree of traffic analysis
resistance.


1.1 Terminology
----------------

   ``Provider`` - A service operated by a third party that Clients
     communicate directly with to communicate with the Mixnet.  It is
     responsible for Client authentication, forwarding outgoing
     messages to the Mixnet, and storing incoming messages for the
     Client. The Provider MUST have the ability to perform
     cryptographic operations on the relayed packets.

   ``Kaetzchen`` - A Provider-side autoresponder service as defined in
     [KAETZCHEN].


1.2 Conventions Used in This Document
-------------------------------------

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
   document are to be interpreted as described in [RFC2119]_.


2. System Overview
==================

The Zcash sender composes a transaction and passes it's serialized
blob form into the protocol. A Sphinx packet is created and is sent
over the mixnet link layer [KATZMIXWIRE] to the entry point, the client's
Provider. This Sphinx packet is routed through the network and the
Provider is the first to remove a layer of Sphinx encryption to find
out what the next hop is. Once the packet arrives at it's destination
Provider, the Zcash transaction Kaetzchen service receives the
transaction submission request.

::

     .--------.        .----------.        .-------.        .-------.       .----------.
     | Sender |  --->  | Provider |  --->  |  Mix  |  --->  |  Mix  |  ---> | Provider |
     `--------'        `----------'        `-------'        `-------'       '----------'


The Kaetzchen JSON request is parsed and the transaction blob is
submitted using the zcashd client RPC. No receipt or acknowledgement
is produced. Handling Zcash transaction failures and the like is
out of scope.


2.1 Protocol Goals
------------------

Our goals include:

* sender unobservability: We desire to prevent any network observer
from learning when a client sends a legitimate Zcash
transaction. Clients therefore periodically send decoy traffic AND
legitimate traffic as described in [LOOPIX] however for this
application we DO NOT NEED loop traffic of any kind, nor do we need
decoy loop traffic.

* client to Zcash transaction unlinkability: We desire to make it very
difficult for active and passive network adversaries to link a specific
transaction to a specific client.


3. Load Balancing Considerations
================================

As mentioned in [KATZMIXNET] the mix network should utilize the
stratified topology to spread the Sphinx packet traffic load. The
mixes present at each strata are added or removed according to the
PKI. Therefore the PKI is used to close the feedback loop for
dynamically adjusting the load on the network.

The load caused by the Zcash transaction submissions can also
similarly be loadbalanced. One or more Zcash submission services can
be operated on the mix network. They will all be advertized in the PKI
consensus document as mentioned in [KAETZCHEN].


X. Anonymity Considerations
===========================

* Using an entry Provider for many uses and for long periods of time
  may be an unnecessary information leakage towards the operator of
  that Provider. Instead it may be preferable to have an "open mixnet"
  where clients can connect to any entry Provider to inject their
  Sphinx packets into the network.


Y. Security Considerations
==========================

* Note that unlike the Katzenpost client to client protocol as
  described in [KATZMIXE2E], this protocol uses a Provider-side
  service [KAETZCHEN] and therefore the Sphinx encryption is
  sufficient to protect the confidentiality and integrity of the
  payload.


Z. Future Work and Research
===========================

 * compose a reliable Zcash submission protocol using this protocol as
   it's basis


Appendix A. References
======================

Appendix A.1 Normative References
---------------------------------

.. [RFC2119]   Bradner, S., "Key words for use in RFCs to Indicate
               Requirement Levels", BCP 14, RFC 2119,
               DOI 10.17487/RFC2119, March 1997,
               <http://www.rfc-editor.org/info/rfc2119>.

.. [KAETZCHEN]  Angel, Y., Kaneko, K., Stainton, D.,
                "Katzenpost Provider-side Autoresponder", January 2018,
                <https://github.com/Katzenpost/docs/blob/master/drafts/kaetzchen.txt>.

.. [KATZMIXWIRE] Angel, Y., "Katzenpost Mix Network Wire Protocol Specification", June 2017.
                 <https://github.com/katzenpost/docs/blob/master/specs/wire-protocol.txt>.

.. [KATZMIXNET]  Angel, Y., Danezis, G., Diaz, C., Piotrowska, A., Stainton, D.,
                "Katzenpost Mix Network Specification", June 2017,
                <https://github.com/Katzenpost/docs/blob/master/specs/mixnet.txt>.

Appendix A.2 Informative References
-----------------------------------

.. [KATZMIXE2E]  Angel, Y., Danezis, G., Diaz, C., Piotrowska, A., Stainton, D.,
                 "Katzenpost Mix Network End-to-end Protocol Specification", July 2017,
                 <https://github.com/katzenpost/docs/blob/master/specs/end_to_end.txt>.
