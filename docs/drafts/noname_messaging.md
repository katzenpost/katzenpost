---
title: "Noname Message Protocol"
description: ""
categories: [""]
tags: [""]
author: ["David Stainton"]
version: 0
draft: true
---

**Abstract**

This document describes the Noname message protocol which is
specifically designed to provide strong location hiding properties,
tunable resistance to longterm statistical disclosure attacks and
resistance to some active attacks. This mix network protocol
essentially provides to clients reliable bidirectional communication
channels. It can be used to construct messaging applications.

## Introduction

This specification is inspired by Pond and Petmail [POND] [PETMAIL]
and also uses many designs from the mix network literature,
especially the [LOOPIX], Katzenpost [KATZMIXNET] and [MIXMINION]
systems. Compared to Katzenpost the system I describe here has a
server side that is almost exactly the same except for the addition
of several Provider-side mixnet services. [KAETZCHEN]

This protocol uses [PANDA] to exchange channel setup information
between clients, this information includes public keys for
encryption AND descriptors of unidirectional dead drops
[KATZDEADDROP]. We use the exchange of unidirectional channels to
form bidirectional channels. We exchange multiple dead drop
descriptors for reliability purposes. The highest protocol
presentation specified here is that of a reliable or optionally
unreliable client to client bidirection communication channel.

This document is meant to be read with the accompanying
specification documents:

- [KATZMIXNET] - Katzenpost Mix Network Specification
- [KATZDECOY] - Katzenpost Mix Network Decoy Traffic Specification
- [KATZMIXPKI] - Katzenpost Mix Network Public Key Infrastructure Specification
- [KATZMIXWIRE] - Katzenpost Mix Network Wire Protocol Specification
- [KAETZCHEN] - Katzenpost Provider-side Autoresponder Extension
- [KATZDEADDROP] - Katzenpost Dead Drop Extension

### 1.1 Conventions Used in This Document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [RFC2119].

### 1.2 Terminology

`ARQ` - Automatic Repeat reQuest, a protocol scheme which
uses ACKnowledgement messages AND retransmissions to achieve
end to end reliability.

`PANDA` - Phrase Automated Nym Discovery Authentication; a
variation of a Password Authenticated Key Exchange where clients
have identical behavior and perform their message exchanges
asynchronously with a simple server which enforces two message
slots per "meeting place". See [PANDA] and [PANDASPEC] for details.

`SURB` - Single Use Reply Block is a cryptographic delivery
token which was first introduced by the Mixminion design
[MIXMINION] and revised by the Sphinx cryptographic packet format.
See [SPHINX] and [SPHINXSPEC] for details.

### 1.3 Differences From The Katzenpost Messaging System

Herein I describe a protocol not a messaging system. We therefore
do not concern ourselves with the end to end encryption but provide
a cryptographic transport. Confidentiality and message integrity are
protected using the link layer [KATZMIXWIRE] and sphinx encryption
layers. [SPHINX] [SPHINXSPEC]

There is no universal naming scheme or inherent SPAM problem, rather
clients are responsible for exchanging the channel initialization
information.

2. System Overview

Mixminion introduced the Single Use Reply Block, also known as a
SURB which is a single-use cryptographic delivery token for latent
message delivery. SURBs have a relatively short lifetime because
they are essentially a mixnet packet header which is encrypted with
the routing keys of several mixes and therefore expires when any of
the mixes rotate their key.

In the Katzenpost system this key rotation epoch is every 3
hours. [KATZMIXPKI] It is NOT desirable to have long lived mix
routing keys because this increases the time allowance of
compulsion attacks. We conclude that SURBs are NOT suitable for
establishing a bidirectional communication channel for clients that
frequently go offline for time durations greater than the mix key
rotation epoch.

Instead a Katzenpost autoresponder [KAETZCHEN] based dead drop
[KATZDEADDROP] service can be used.  Unlike SURBs dead drop
descriptors do not have any inherent expiration. However, for the
purpose of reducing exposure to longterm statistical disclosure
attacks, these descriptors shall specify an expiration. The
expiration specifies how far into the future the receiver promises
to check for messages in the dead drop queue. Client communication
partners MUST periodically exchange new dead drop descriptors
before the old dead drop descriptors expire.

## 3. Threat Model

### 3.1 Security Goals

This specification document describes a messaging system with
the following security goals:

Strong location hiding properties: The system MUST NOT give
Bob enough information to easily find Alice's location AND if
a compulsion attack is used it MUST require compromising more
than one mixnet node.

Sender and receiver anonymity with respect to third party
observers: Bob and Alice send each other messages while being
certain of who will receive the messages AND while not hiding
their identity to the receiver. However, third party observers
will NOT be able to determine that they are even communicating
with each other.

```
* receiver unobservability: Receivers receive decoy traffic and
legit traffic thereby creating uncertainty for passive network
observers.

* sender unobservability: Senders send decoy and legit traffic
thereby creating uncertainly for passive network observers.
```

We shall now proceed with Brian Warner's mode of analysis and
quote several security goals from the [PETMAIL] document :

```
* S0: Two different senders cannot tell if they're talking to the
same recipient or not.

* M0: The mailbox server cannot tell which message came from which
sender, not even that two messages came from the same sender, nor
can it determine how many senders might be configured for each
recipient.

* R0: The recipient can use the transport information to accurately
identify the sender.

* Rev0: R can revoke one sender without involving the remaining ones.
```

Our security goals in short form are expressed as:

```
S0 M0 R0 Rev0
```

## 4. Protocol Description

Each client performs the [PANDA] protocol exchange using
their shared passphrase. This allows clients to establish
a Single Double Ratchet connection using Katzenpost dead drops.

Our four point protocol plan is as follows:

1. register a remote mailbox as the dead drop for the new contact
2. create signal double ratchet keys and compose a dead drop descriptor
3. perform the PANDA exchange
4. send and receive messages

X. Future Work

* a more formal security analysis
* Post Quantum double ratchet instead of Signal Double Ratchet
* can we use Sphinc-256 signatures for anything? ;-p

Y. Anonymity Considerations
Z. Security Considerations

Appendix A. References

Appendix A.1 Normative References

[RFC2119]
Bradner, S.,
"Key words for use in RFCs to Indicate Requirement Levels",
BCP 14, RFC 2119,
DOI 10.17487/RFC2119,
March 1997,
http://www.rfc-editor.org/info/rfc2119

[LOOPIX]
Piotrowska, A., Hayes, J., Elahi, T., Meiser, S., Danezis, G.,
“The Loopix Anonymity System”,
USENIX,
August 2017,
https://arxiv.org/pdf/1703.00536.pdf

[POND]
Langley, A.,
"Pond",
November 2012,
https://github.com/agl/pond/tree/master/doc

[KATZMIXNET]
Angel, Y., Danezis, G., Diaz, C., Piotrowska, A., Stainton, D.,
"Katzenpost Mix Network Specification",
June 2017,
https://github.com/katzenpost/katzenpost/blob/main/docs/specs/mixnet.md

[KATZDECOY] 
Angel, Y., Danezis, G., Diaz, C., Piotrowska, A., Stainton, D.,
"Katzenpost Mix Network Decoy Traffic Specification",
https://github.com/katzenpost/katzenpost/blob/main/docs/drafts/decoy_traffic.md

[KATZMIXPKI]
Angel, Y., Piotrowska, A., Stainton, D.,
"Katzenpost Mix Network Public Key Infrastructure Specification",
December 2017,
https://github.com/katzenpost/katzenpost/blob/main/docs/specs/pki.md

[KATZMIXWIRE]
Angel, Y.,
"Katzenpost Mix Network Wire Protocol Specification",
June 2017.
https://github.com/katzenpost/katzenpost/blob/main/docs/specs/wire-protocol.md

[SPHINXSPEC]
Angel, Y., Danezis, G., Diaz, C., Piotrowska, A., Stainton, D.,
"Sphinx Mix Network Cryptographic Packet Format Specification"
July 2017,
https://github.com/katzenpost/katzenpost/blob/main/docs/specs/sphinx.md

[LIONESS]
Angel, Y.,
"The LIONESS Wide-Block-Cipher",
2017,
https://github.com/katzenpost/katzenpost/blob/main/docs/specs/lioness.md

[RFC7748]
Langley, A., Hamburg, M., and S. Turner,
"Elliptic Curves for Security",
RFC 7748,
January 2016.

[KAETZCHEN]
Angel, Y., Kaneko, K., Stainton, D.,
"Katzenpost Provider-side Autoresponder",
January 2018,
https://github.com/katzenpost/katzenpost/blob/main/docs/specs/kaetzchen.md

[KATZDEADDROP]
Stainton, D.,
"Katzenpost Dead Drop Extension",
February 2018,
https://github.com/katzenpost/katzenpost/blob/main/docs/drafts/deaddrop.md

[KATZPANDA]
Stainton, D.,
"Katzenpost PANDA Autoresponder Extension",
March 2018,
https://github.com/katzenpost/katzenpost/blob/main/docs/drafts/panda.md

Appendix A.2 Informative References

[SHAKE]
"SHA-3 STANDARD: PERMUTATION-BASED HASH AND EXTENDABLE OUTPUT FUNCTIONS",
https://csrc.nist.gov/csrc/media/publications/fips/202/final/documents/fips_202_draft.pdf

[RFC7539]
Nir, Y. and A. Langley,
"ChaCha20 and Poly1305 for IETF Protocols",
RFC 7539, DOI 10.17487/RFC7539,
May 2015,
http://www.rfc-editor.org/info/rfc7539

[RFC7693]
Saarinen, M-J., Ed., and J-P. Aumasson,
"The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)",
RFC 7693, DOI 10.17487/RFC7693,
November 2015,
http://www.rfc-editor.org/info/rfc7693

[SIGNAL]
Perrin, T., Marlinspike, M.,
"The Double Ratchet Algorithm",
November 2016,
https://signal.org/docs/specifications/doubleratchet/

[NOISE]
Perrin, T.,
"The Noise Protocol Framework",
May 2017,
https://noiseprotocol.org/noise.pdf

[PETMAIL]
Warner, B.,
"Petmail mailbox-server delivery protocol",
Proceedings of Brian Warner's blog,
July 2015,
http://www.lothar.com/blog/53-petmail-delivery/

[MIXMINION]
Danezis, G., Dingledine, R., Mathewsom, N.,
"Mixminion: Design of a Type III Anonymous Remailer Protocol"
https://www.mixminion.net/minion-design

[SPHINX]
Danezis, G., Goldberg, I.,
"Sphinx: A Compact and Provably Secure Mix Format",
DOI 10.1109/SP.2009.15,
May 2009,
http://research.microsoft.com/en-us/um/people/gdane/papers/sphinx-eprint.pdf

[PANDA]
Appelbaum, J.,
"Going Dark: Phrase Automated Nym Discovery Authentication",
https://github.com/agl/pond/tree/master/papers/panda

[PANDASPEC] 

[FORWARDMIX]
Danezis, G., "Forward Secure Mixes",
In the Proceedings of 7th Nordic Workshop on Secure IT Systems,
November 2002,
https://www.freehaven.net/anonbib/cache/Dan:SFMix03.pdf

[COMPULS05]
Danezis, G., Clulow, J., "Compulsion Resistant Anonymous Communications",
Proceedings of Information Hiding Workshop,
June 2005,
https://www.freehaven.net/anonbib/cache/ih05-danezisclulow.pdf

[FINGERPRINTING]
Danezis, G., Clayton, R.,
"Route Finger printing in Anonymous Communications",
https://www.cl.cam.ac.uk/~rnc1/anonroute.pdf

[BRIDGING]
Danezis, G., Syverson, P.,
"Bridging and Fingerprinting: Epistemic Attacks on Route Selection",
In the Proceedings of PETS 2008, Leuven, Belgium,
July 2008,
https://www.freehaven.net/anonbib/cache/danezis-pet2008.pdf>.

[LOCALVIEW]
Gogolewski, M., Klonowski, M., Kutylowsky, M.,
"Local View Attack on Anonymous Communication",
https://www.freehaven.net/anonbib/cache/esorics05-Klonowski.pdf>.

[HEARTBEAT03]
Danezis, G., Sassaman, L.,
"Heartbeat Traffic to Counter (n-1) Attacks",
Proceedings of the Workshop on Privacy in the Electronic Society,
October 2003,
https://www.freehaven.net/anonbib/cache/danezis:wpes2003.pdf

[MIRANDA]
Leibowitz, H., Piotrowska, A., Danezis, G., Herzberg, A.,
"No right to ramain silent: Isolating Malicious Mixes"
2017,
https://eprint.iacr.org/2017/1000.pdf

[MIXRELIABLE]
Dingledine, R., Freedman, M., Hopwood, D., Molnar, D.,
"A Reputation System to Increase MIX-Net Reliability",
In Information Hiding, 4th International Workshop,
2001,
https://www.freehaven.net/anonbib/cache/mix-acc.pdf

[YEE02]
Yee, Ka-Ping., "User Interaction Design for Secure Systems",
Computer Science Department, University of California, Berkeley,
May 2002
http://zesty.ca/pubs/csd-02-1184.pdf
