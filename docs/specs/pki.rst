.. _pki:

Katzenpost Mix Network Public Key Infrastructure Specification
**************************************************************

| Yawning Angel
| Ania Piotrowska
| David Stainton

Version 0

.. note:: by david

    we need to make sure
    the schema in our implemention matches this spec.
    https://github.com/Katzenpost/authority
    (for the time being our authority is a nonvoting single point of failure)

    should we make this a threshold vote instead of total consensus?

    are there other failure cases that we should mention?

.. rubric:: Abstract

This document describes the message formats and protocols of a
decryption mix network public key infrastructure system. It has some
specific design features which aid in traffic analysis resistance.
This document is meant to serve as an implementation guide.

.. contents:: :local:

1. Introduction
===============

   Mixnets are designed with the assumption that a PKI exists and it
   gives each client the same view of the network. This specification
   is inspired by the Tor and Mixminion Directory Authority systems
   [MIXMINIONDIRAUTH]_ [TORDIRAUTH]_ whose main features are precisely what
   we need in our PKI. These are decentralized systems meant to be
   collectively operated by multiple entities.

   The mix network directory authority system (PKI) is essentially a
   cooperative decentralized database and voting system that is used
   to produce network consensus documents which mix clients
   periodically retrieve and use for their path selection algorithm
   when creating Sphinx packets. These network consensus documents are
   derived from a voting process between the Directory Authority
   servers.

   This design prevents mix clients from using only a partial view of
   the network for their path selection so as to avoid fingerprinting
   and bridging attacks [FINGERPRINTING]_ [BRIDGING]_ [LOCALVIEW]_.

   The PKI is also used by Authority operators to specify network-wide
   parameters, for example in the Katzenpost Decryption Mix Network
   [KATZMIXNET]_ the Poisson mix strategy is used and therefore all the
   clients must use the same lambda parameter for their exponential
   distribution function when choosing hop delays in the path
   selection. The Mix Network Directory Authority system aka PKI
   SHALL be used to distribute such network-wide parameters in the network
   consensus document that have an impact on security and performance.

1.1 Conventions Used in This Document
-------------------------------------

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
   document are to be interpreted as described in [RFC2119].

1.2 Terminology
---------------

   ``PKI`` - public key infrastructure

   ``Directory Authority system`` - refers to specific PKI schemes used by
                                Mixminion and Tor

   ``MSL`` - maximum segment lifetime

   ``mix descriptor`` - A database record which describes a component mix

   ``family`` - Identifier of security domains or entities operating one
            or more mixes in the network. This is used to inform the
            path selection algorithm.

   ``nickname`` - simply a nickname string that is unique in the consensus
              document; see "Katzenpost Mix Network Specification"
              section "2.2. Network Topology".

   ``layer`` - The layer indicates which network topology layer a
           particular mix resides in.

   ``Provider`` - A service operated by a third party that Clients
              communicate directly with to communicate with the Mixnet.
              It is responsible for Client authentication,
              forwarding outgoing messages to the Mixnet, and storing incoming
              messages for the Client. The Provider MUST have the ability to
              perform cryptographic operations on the relayed messages.

2. Overview of Mix PKI Interaction
==================================

   Each Mix MUST rotate the key pair used for Sphinx packet processing
   periodically for forward secrecy reasons and to keep the list of
   seen packet tags short. [SPHINX09]_ [SPHINXSPEC]_ The Katzenpost Mix
   Network uses a fixed interval (``epoch``), so that key rotations happen
   simultaneously throughout the network, at predictable times.

   Each Directory Authority server and Client MUST use NTP or other time
   synchronization protocol in order to correctly use this protocol.

   Let each epoch be exactly ``10800 seconds (3 hours)`` in duration, and
   the 0th Epoch begin at ``2017-06-01 00:00 UTC``.

   To facilitate smooth operation of the network and to allow for
   delays that span across epoch boundaries, Mixes MUST publish keys
   to the PKI for at least 3 epochs in advance, unless the mix will
   be otherwise unavailable in the near future due to planned downtime.

   Thus, at any time, keys for all Mixes for the Nth through N + 2nd
   epoch will be available, allowing for a maximum round trip (forward
   message + SURB) delay + transit time of 6 hours.

2.1 PKI Protocol Schedule
-------------------------

2.1.1 Directory Authority Server Schedule
-----------------------------------------

   Directory Authority server interactions are conducted according to
   the following schedule, where ``T`` is the beginning of the current epoch.

   ``T``                         - Epoch begins

   ``T + 2 hours``               - Vote exchange

   ``T + 2 hours + 7.5 minutes`` - Tabulation and signature exchange

   ``T + 2 hours + 15 minutes``  - Publish consensus


2.1.2 Mix Schedule
------------------

   Mix PKI interactions are conducted according to the following
   schedule, where T is the beginning of the current epoch.

    ``T + 2 hours``              - Deadline for publication of all mixes documents
                               for the next epoch.

    ``T + 2 hours + 15 min``     - Start attempting to fetch PKI documents.

    ``T + 2 hours + 30 min``     - Start establishing connections to the new set of
                               relevant mixes in advance of the next epoch.

    ``T + 3 hours - 1MSL``       - Start accepting new Sphinx packets encrypted to
                               the next epoch's keys.

    ``T + 3 hours + 1MSL``       - Stop accepting new Sphinx packets encrypted to
                               the previous epoch's keys, close connections to
                               peers no longer listed in the PKI documents and
                               erase the list of seen packet tags.

   As it stands, mixes have ~2 hours to publish, the PKI has 15 mins
   to vote, and the mixes have 28 mins to establish connections before
   there is network connectivity failure.

2.2 Scheduling Mix Downtime
---------------------------

   Mix operators can publish a half empty mix descriptor for future
   epochs to schedule downtime. The mix descriptor fields that MUST
   be populated are:

   * ``Version``
   * ``Name``
   * ``Family``
   * ``Email``
   * ``Layer``
   * ``IdentityKey``
   * ``MixKeys``

   The map in the field called "MixKeys" should reflect the scheduled
   downtown for one or more epochs by not have those epochs as keys in
   the map.

3. Voting for Consensus Protocol
================================

   In our Directory Authority protocol, all the actors conduct their
   behavior according to a common schedule as outlined in section "2.1
   PKI Protocol Schedule". The Directory Authority servers exchange
   messages to reach consensus about the network. Other tasks they
   perform include collecting mix descriptor uploads from each mix for
   each key rotation epoch, voting, signature exchange and publishing
   of the network consensus documents.

3.1 Protocol Messages
---------------------

   There are only two message types in this protocol:

   * ``mix_descriptor``: A mix descriptor describes a mix.

   * ``directory``: A directory contains a list of descriptors and other
     information that describe the mix network.

   Mix descriptor and directory documents MUST be properly signed.

3.1.1 Mix Descriptor and Directory Signing
------------------------------------------

   Mixes MUST compose mix descriptors which are signed using their
   private identity key, an ed25519 key. Directories are signed by one
   or more Directory Authority servers using their authority key, also
   an ed25519 key. In all cases, signing is done using JWT [RFC7515]_.

3.2 Vote Exchange
-----------------

   As described in section "2.1 PKI Protocol Schedule", the Directory
   Authority servers begin the voting process 2 hours after epoch
   beginning.  Each Authority exchanges vote directory messages with
   each other.

   Authorities archive votes from other authorities and make them
   available for retreival. Upon receiving a new vote, the authority
   examines it for new descriptors and fetches them from that
   authority. It includes the new descriptors in the next epoch's
   voting round.

3.3 Vote Tabulation for Consensus Computation
---------------------------------------------

   The main design constraint of the vote tabulation algorithm is that
   it MUST be a deterministic process that produces that same result
   for each directory authority server. This result is known as a
   network consensus file. Such a document is a well formed directory
   struct where the "status" field is set to "consensus" and contains
   0 or more descriptors, the mix directory is signed by 0 or more
   directory authority servers. If signed by the full voting group
   then this is called a fully signed consensus.

   1. Validate each vote directory:
      - that the liveness fields correspond to the following epoch
      - status is "vote"
      - version number matches ours

   2. Compute a consensus directory:
      Here we include a modified section from the Mixminion PKI spec
      [MIXMINIONDIRAUTH]_:

      - For each distinct mix identity in any vote directory:
            - If there are multiple nicknames for a given identity, do not
              include any descriptors for that identity.
            - If half or fewer of the votes include the identity, do not
              include any descriptors for the identity.  [This also
              guarantees that there will be only one identity per nickname.]
            - If we are including the identity, then for each distinct
              descriptor that appears in any vote directory:
                - Do not include the descriptor if it will have expired
                  on the date the directory will be published.
                - Do not include the descriptor if it is superseded by
                  other descriptors for this identity.
                - Do not include the descriptor if it not valid in the
                  next epoch.
                - Otherwise, include the descriptor.

      - Sort the list of descriptors by the signature field so that
        creation of the consensus is reproducible.
      - Set directory "status" field to "consensus".

3.4 Signature Collection
------------------------

   Each Authority exchanges their newly generated consensus files with
   each other.  Upon receiving signed consensus documents from the
   other Authorities, peer signatures are appended to the current
   local consensus file if the signed contents match. The Authority
   SHOULD warn the administrator if network partition is detected.

3.5 Publication
---------------

   If the consensus is signed by all members of the voting group then
   it's a valid consensus and it is published. Otherwise if there is
   disagreement about the consensus directory, each authority collects
   signatures from only the servers which it agrees with about the
   final consensus.

   Upon consensus failure detection, the Directory Authority SHOULD
   report to its administrator that the consensus has failed, and
   explain how. Passive consumer clients downloading the network
   consensus documents SHOULD also receive a warning or error message.

4. PKI Protocol Data Structures
===============================

4.1 Mix Descriptor Format
-------------------------

   Note that there is no signature field. This is because mix
   descriptors are serialized and signed using JWT. The
   ``IdentityKey`` field is a public ed25519 key.  The ``MixKeys`` field
   is a map from epoch to public X25519 keys which is what the Sphinx
   packet format uses.

   .. code::

    {
        "Version": 0,
        "Name": "",
        "Family": "",
        "Email": "",
        "AltContactInfo":"",
        "IdentityKey": "",
        "LinkKey":"",
        "MixKeys": {
            "Epoch": "EpochPubKey",
        },
        "Addresses": ["IP:Port"],
        "Layer": 0,
        "LoadWeight":0
      }

4.2 Directory Format
--------------------

   .. code::

    {
        "Signatures": [],
        "Version": 0,
        "Status": "vote",
        "Lambda" : 0.274,
        "MaxDelay" : 30,
        "Topology" : [],
        "Providers" : [],
    }

5. PKI Wire Protocol
====================

   The wire protocol is built using HTTP. The following URLs for
   publishing and retrieving are constructed using SERVER and EPOCH
   where SERVER is the address of the Directory Authority server and
   EPOCH is the integery indicating the epoch as described in section
   "2. Overview of Mix PKI Interaction".

5.1. Retrieving a directory
---------------------------

   A directory may be retreived from a Directory Authority server with
   a URL of the form:

      http://SERVER/v0/get/EPOCH

5.2. Publishing a mix descriptor
--------------------------------

   A mix descriptor may be uploaded to a Directory Authority server with
   a URL of the form:

      http://SERVER/v0/post/EPOCH

6. Future Work
==============

   * PQ crypto signatures for all PKI documents: mix descriptors and
     directories. [SPHINCS256]_ could be used, we already have a golang
     implementation: https://github.com/Yawning/sphincs256/

   * load balancing: Make a Bandwidth Authority system to measure mix
     capacity as describe in [PEERFLOW]_.

   * implement byzantine attack defenses as described in [MIRANDA]_
     where mix link performance proofs are recorded and voted on by
     Directory Authorities using a threshold signature scheme.

   * choose a better wire protocol

   * choose a better schema language

7. Anonymity Considerations

   * This system is intentionally designed to provide identical
     network consensus documents to each mix client. This mitigates
     epistemic attacks against the client path selection algorithm
     such as fingerprinting and bridge attacks [FINGERPRINTING]_
     [BRIDGING]_.

   * If consensus has failed and thus there is more than one consensus
     file, clients MUST NOT use this compromised consensus and instead
     fallback to the previous consensus or refuse to run.

8. Security Considerations
==========================

   * The Directory Authority/PKI system for a given mix network is
     essentially the root of all authority in the system. This implies
     that if the PKI as a whole becomes compromised then so will the
     rest of the system (the component mixes) in terms of providing
     the main security properties described as traffic analysis
     resistance. Therefore a decentralized systems architecture is
     used so that the system is more resiliant when attacked, in
     accordance with the principle of least authority which gives us
     security by design not policy. [SECNOTSEP]_ Otherwise, reducing the
     operation of the PKI system to a single host creates a terrible
     single point of failure where attackers can simply compromise
     this single host to control the network consensus documents that
     mix clients download and use to inform their path selection.

   * We do not require cryptographic authenticity properties from the
     network transport because all our messages already have a
     cryptographic signature field that MUST be checked by the
     receiving peer. Confidentiality is not required because clients
     should all receive the exact same consensus file with all the
     signatures to prove it's origins.

     If a passive network adversary can watch the Directory Authority
     servers vote, that's OK. However, very paranoid implementers
     could disagree and use our Noise based PQ crypto wire protocol
     [KATZMIXWIRE]_ for Directory Authority system message exchange as
     was suggested in section "6. Future Work".

   * Constructing this consensus protocol using a cryptographically
     malleable transport could expose at least one protocol parser to
     the network, this represents a small fraction of the attack
     surface area.

9. Acknowledgements
===================

   I would like to thank Nick Mathewson for answering design questions.

Appendix A. References
======================

Appendix A.1 Normative References
---------------------------------

   [RFC2119]_  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119,
              DOI 10.17487/RFC2119, March 1997,
              <https://www.rfc-editor.org/info/rfc2119>.

   [RFC7515]_  Jones, M., Bradley, J., Sakimura, N.,
              "JSON Web Signature (JWS)", May 2015,
              <https://tools.ietf.org/html/rfc7515>.

Appendix A.2 Informative References
-----------------------------------

.. [MIXMINIONDIRAUTH] Danezis, G., Dingledine, R., Mathewson, N.,
                      "Type III (Mixminion) Mix Directory Specification",
                      December 2005, <https://www.mixminion.net/dir-spec.txt>.

.. [TORDIRAUTH]  "Tor directory protocol, version 3",
                 <https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt>.

.. [FINGERPRINTING] "Route Finger printing in Anonymous Communications",
                    <https://www.cl.cam.ac.uk/~rnc1/anonroute.pdf>.

.. [BRIDGING] Danezis, G., Syverson, P.,
              "Bridging and Fingerprinting: Epistemic Attacks on Route Selection",
              In the Proceedings of PETS 2008, Leuven, Belgium, July 2008,
              <https://www.freehaven.net/anonbib/cache/danezis-pet2008.pdf>.

.. [LOCALVIEW] Gogolewski, M., Klonowski, M., Kutylowsky, M.,
               "Local View Attack on Anonymous Communication",
               <https://www.freehaven.net/anonbib/cache/esorics05-Klonowski.pdf>.

.. [KATZMIXNET]  Angel, Y., Danezis, G., Diaz, C., Piotrowska, A., Stainton, D.,
                "Katzenpost Mix Network Specification", June 2017,
                <https://github.com/Katzenpost/docs/blob/master/specs/mixnet.txt>.

.. [SPHINX09]  Danezis, G., Goldberg, I., "Sphinx: A Compact and
               Provably Secure Mix Format", DOI 10.1109/SP.2009.15, May 2009,
               <http://research.microsoft.com/en-us/um/people/gdane/papers/sphinx-eprint.pdf>.

.. [SPHINXSPEC] Angel, Y., Danezis, G., Diaz, C., Piotrowska, A., Stainton, D.,
                "Sphinx Mix Network Cryptographic Packet Format Specification"
                July 2017, <https://github.com/Katzenpost/docs/blob/master/specs/sphinx.txt>.

.. [SPHINCS256] Bernstein, D., Hopwood, D., Hulsing, A., Lange, T.,
                Niederhagen, R., Papachristodoulou, L., Schwabe, P., Wilcox
                O'Hearn, Z., "SPHINCS: practical stateless hash-based signatures",
                <http://sphincs.cr.yp.to/sphincs-20141001.pdf>.

.. [PEERFLOW] Johnson, A., Jansen, R., Segal, A., Syverson, P.,
              "PeerFlow: Secure Load Balancing in Tor",
              Preceedings on Privacy Enhancing Technologies, July 2017,
              <https://petsymposium.org/2017/papers/issue2/paper12-2017-2-source.pdf>.

.. [MIRANDA] Leibowitz, H., Piotrowska, A., Danezis, G., Herzberg, A., 2017,
             "No right to ramain silent: Isolating Malicious Mixes"
             <https://eprint.iacr.org/2017/1000.pdf>.

.. [SECNOTSEP] Miller, M., Tulloh, B., Shapiro, J.,
               "The Structure of Authority: Why Security Is not a Separable Concern",
               <http://www.erights.org/talks/no-sep/secnotsep.pdf>.

.. [KATZMIXWIRE] Angel, Y. "Katzenpost Mix Network Wire Protocol Specification", June 2017,
                <https://github.com/Katzenpost/docs/blob/master/specs/wire-protocol.txt>.
