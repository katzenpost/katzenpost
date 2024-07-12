---
title: "The Katzenpost Decryption Mix Network Anonymity System: fast, safe and correct mixnet protocol design"
description: ""
categories: [""]
tags: [""]
author: ["Yawning Angel", "George Danezis", "Claudia Diaz", "Ania Piotrowska", "David Stainton"]
version: 0
draft: true
---

**Abstract**

This document describes the high level architecture and design of the
Katzenpost Decryption Mix Network. Here we also present a novel
multidisciplinary approach to mix network protocol design which
introduces design ideas from the packet switching network literature
used in concert with the latest innovations in mix network design from
the Loopix anonymity system [LOOPIX].

## Introduction

Here we present cryptographic messaging system which uses many Loopix
designs such as Poisson mix strategy, decoy traffic and Sphinx packet
format. We add to these designs a new reliable network transport
protocol for decryption mix networks called the Poisson Stop and Wait
ARQ. In our new messaging system, clients utilize this unidirectional,
half-duplex protocol to reliably deliver messages to the message
recipient's Provider. The Provider will queue the message ciphertext
until it is retrieved by the recipient client.

Other packet switching techniques are also applied here to mix
networks, such as appropriate used of modern AQMs (active queue
management) algorithms for various purposes such as: preventing buffer
bloat, preventing congestion collapse, maintaining flow QoS,
mitigating DDoS attacks et cetera.

Our messaging system uses a federated e-mail protocol overlay to
facilitate user interaction and client interoperability. That is to
say, any existing e-mail client can be used to send messages to the
local SMTP submission proxy which proxies messages to the mix network.
Message retrieval is also done using any ordinary e-mail client
interacting with the local POP3 retrieval proxy daemon. This daemon
connects to the user's mixnet Provider(s), retrieves queued message
ciphertext and decrypts the messages making them available for
retrieval locally by POP3.

## Terminology

- ACK: a protocol acknowledgement message used to achieve reliability in ARQ schemes
- ARQ: Automatic Repeat reQuest, a reliable network protocol utilizing automatic repeat request
- AQM: Active Queue Management
- SURB: Single Use Reply Block

## System Overview

Unlike the Tor Network, this system is not volunteer
operated. Operators are a part of a fixed set who all agree to
cooperatively run an equal size set of mixes and network perimeter
points, also known as Providers, which are responsible for
authenticating clients, proxying Sphinx packets to the mix network and
queuing Sphinx packet payloads on behalf of recipient Clients.

Our mix network design uses the stratified mix network topology.
Providers collectively represent the mix network perimeter layer and
therefore the Providers have a fixed subset of mixes that they can
send messages to and another set they can receive messages
from. [MIXTOPO10] As we shall see later in this presentation, this
topology makes it easier to reason about the performance of packet
queues/AQMs as well as DDoS defenses. These are not the main themes of
our work but merely an interesting secondary benefit of our approach
to protocol design.

Component mixes use the Poisson mix strategy [KESDOGAN98] however the
Client message send rate can be changed to implement a congestion
management backoff strategy. The literature generally suggests that an
exponential backoff for retransmissions is necessary to prevent
congestion collapse and to maintain flow fairness. [CONGAVOID]
[SMODELS] In the case of our Loopix inspired design, we could
dynamically shape client's traffic send rate based on packetloss and
or explicit congestion notifications.  Usage of predetermined
transmission intervals that are exponentially backed-off can be
used. [RFC5404] However, it is also possible to prevent congestion
collapse without using dynamic algorithms, but a much more simple
approach: Providers can perform rate limiting and enforce maximum
concurrent connection limitations in order to prevent congestion
collapse.

Several classes of decoy traffic are used as described in the Loopix
paper to resist end to end Client message correlation. It should also
be noted that several sizes of Sphinx packets are used and therefore
the classes of dummy traffic are multiplied by the number of sizes.
For simplicity we choose two sizes of Sphinx packets for message
transmission and one size for protocol acknowledgements for a total of
three Sphinx packet sizes.

Users may use existing e-mail client software by running a local SMTP
submission proxy and a POP3 receive proxy. That is, the receive and
submission proxies are essentially the mixnet client however it is
designed to interoperate with existing e-mail clients so that a user
can be totally unaware of the cryptographic message and mix network
complexities. We've written about our local SMTP submission and
receive POP3 proxy designs, however we've also specified the design
of an existing e-mail software with user interaction design modifications
suited for our end to end mixnet messaging protocol:

"Katzenpost Decryption Mix Network User Interface Design"

## Layers of Mix Network Encryption

```
diagram of mixnet crypto protocol layer cake
```

`link layer` - The mix network link layer consists of TCP and an
interactive Noise protocol pattern.  Our Noise-based link layer
crypto is post-quantum and uses
Noise_NNhfs_25519+NewHope-Simple_ChaChaPoly_Blake2b, described in:

```
Katzenpost Mix Network Wire Protocol Specification
```

`mix packets` - The Sphinx mix cryptographic packet format is used to
send mix network messages. Our implementation uses X25519,
HMAC-SHA256-128, HKDF-SHA256, CTR-AES128, AEZv5.  as described in:

```
Sphinx Mix Network Cryptographic Packet Format Specification
```

`mix packet payload` - Mix network messages are encrypted end to end
by mix network Clients using Noise_X_25519_ChaChaPoly_Blake2b,
a one-way Noise framework pattern. [NOISE17] Details can be found in:

```
Katzenpost Mix Network End-to-end Protocol Specification
```

The Poisson Stop and Wait Automatic Repeat Request Protocol

**Stop and Wait ARQ timeline diagram**

Stop and Wait ARQ is the most simple protocol design that achieves
reliability [ARQ17] where the sender uses a transmission window of
size one. This means that after a protocol data unit is transmitted
the sender waits for an ACK before sending another protocol data unit.
If the ACK is not received within the protocol timeout duration then a
retransmission is performed. The Stop and Wait ARQ design has very low
channel utilization but as we shall soon explain, it's advantage for
use with Mix Networks is that it leaks less information.

Our variant of Stop and Wait ARQ is used by clients to send messages
to Providers rather than Client to Client so as to only require the
sending Client to remain online.  However, if the sending client
disconnects before receiving an ACK from the destination Provider,
then the ACK will later be queued in the Client's Provider.  If
however packetloss or a Mix outage has prevented the sending Client's
sent message from arriving at it's destination Provider, then upon
reconnecting to the Provider, the Client will not find an ACK message
in it's queue. Upon finding no ACK within the timeout duration, the
client will retransmit the message. The full path selection algorithm
is used for retransmissions.

These forward Sphinx packet payloads contain message ciphertext as
well as a Single Use Reply Block which the Providers use to send the
ACK messages.  This peculiar situation of receiving the reply channel
from within the forward packet payload makes this protocol half duplex
similar to various acoustic network mediums many of which also use
Stop and Wait ARQ.

**Setting the Stop and Wait Timeout durations**

Normally, Stop and Wait ARQ implementations would apply knowledge of a
smoothed RTT estimate for dynamically adjusting protocol
timers. However in our mix network case we are utilizing the Poisson
mix strategy which means that the client chooses the mix delays for
each hop. These delays are sampled from an exponential distribution
function and could be dynamically tuned for congestion management
purposes.  Therefore the client always knows the approximate
propagation delay for each mixnet messages and adds some slop to account
for network congestion delays and endpoint processing delays. This
means that protocol timers are set in accordance to the per-hop delays
encoded in the Sphinx headers for the forward message and the reply
block used for the ACK, a protocol control message.

**Stop and Wait ARQ Channel Efficiency**

(Discuss Stop and Wait ARQ channel efficiency characteristics.)

```
R = link rate
frame_size = frame size
frame_header_size = size of frame header
ack_size = ack size
t_prop = processing delay
t0 = 2 * t_prop + 2 * t_prop + frame_size/R + ack_size/R
```

effective transmission rate:

```
R0eff = (frame_size - frame_header_size)/t0
```

transmission efficiency:

```
efficiency = ((frame_size - frame_header_size)/t0) / R
```

Internal queues used to compose component mixes

Component mixes are composed of three packet queues, an ingress queue,
a mix strategy queue and an egress queue (referred to in the TCP
literature as a congestion window). Mixes use CoDel [CODEL17] for their
ingress AQM to avoid buffer bloat, the state where queue delays grow
large enough to negatively impact connection quality of service by
inducing high packet latency.  Whereas Providers use a variant of
Resiliant Stochastic Fair Blue AQM [RSFBLUE] [SFBLUE] for their
ingress AQM since they alone have Client IP address visibility and
therefore can distinguish traffic flows with a per-Client granularity
and provide some measure of fairness and potential DDoS protection.

**Link Layer Congestion Considerations**

A KIST scheme should be utilized whenever TCP is used to avoid
suboptimal mixnet packet send scheduling to adjacent mixes. [KIST14]

**Explicit Congestion Notification**

Classical network protocol literature often describes implicit
upstream congestion signaling via packetloss, however various explicit
congestion notification schemes have also been designed.  Unless the
mix network latency is very low, an explicit notification system MUST
be used. The purpose of such a system is to notify Clients that they
should reduce their packet transmission rate.

In our mix network system we use a wire protocol command for this
purpose called "Source Quench" which is similar in design to ICMP
Source Quench [RFC896].  The Source Quench originates from mixes who's
ingress queue drops packets. These Source Quench commands propagate
from congested mix to the Providers who then broadcast the Source
Quench to all of their connected clients.

Alternatively, the Client-Provider protocol could require the Provider
to reply to Send Packet commands with Packet Received commands such
that a variant of Stop and Wait ARQ is formed.

**Non-TCP Link Layer Performance Advantages**

- no head-of-line blocking performance issues
- KIST scheme not needed because implementation of the link layer protocol must handle scheduling explicitly

## Future Research

It should be informative to utilize ns-3, the network simulator to
simulate mix networks.  This could help us answer security and
performance questions about our design and lead to new design
iterations. For instance, use ns-3 to determine if a given ARQ scheme
can lead to congestion collapse, to compare connection QoS on a
loaded mixnet composed of mixes which use the CoDel AQM versus drop
tail, determine if a fair AQM on the perimeter can protect the
mixnet from a DoS or DDoS attack et cetera.


## References

[LOOPIX]
Piotrowska, A., Hayes, J., Elahi, T., Meiser, S.,
and Danezis, G., “The Loopix Anonymity System”,
USENIX,
August, 2017
https://arxiv.org/pdf/1703.00536.pdf

[SPHINX09]
Danezis, G., Goldberg, I., "Sphinx: A Compact and
Provably Secure Mix Format", DOI 10.1109/SP.2009.15,
May 2009,
http://research.microsoft.com/en-us/um/people/gdane/papers/sphinx-eprint.pdf

[KESDOGAN98]
Kesdogan, D., Egner, J., and Büschkes, R.,
"Stop-and-Go-MIXes Providing Probabilistic Anonymity in an Open System."
Information Hiding,
1998.

[MIXTOPO10]
Diaz, C., Murdoch, S., Troncoso, C., "Impact of Network Topology on Anonymity
and Overhead in Low-Latency Anonymity Networks",
PETS,
July 2010,
https://www.esat.kuleuven.be/cosic/publications/article-1230.pdf

[CONGAVOID]
Jacobson, V., Karels, M., "Congestion Avoidance and Control",
Symposium proceedings on Communications architectures and protocols,
November 1988,
http://ee.lbl.gov/papers/congavoid.pdf

[SMODELS]
Kelly, F., "Stochastic Models of Computer Communication Systems",
Journal of the Royal Statistical Society, 1985,
http://www.yaroslavvb.com/papers/notes/kelly-stochastic.pdf?origin=publication_detail

[RFC896]
Nagle, J., "Congestion Control in IP/TCP Internetworks",
January 1984,
https://tools.ietf.org/html/rfc896

[KIST14]
Jansen, R., Geddes, J., Wacek, C., Sherr, M., Syverson, P.,
"Never Been KIST: Tor’s Congestion Management Blossoms with Kernel-Informed Socket Transport",
Proceedings of 23rd USENIX Security Symposium, August 2014,
https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-jansen.pdf

[NOISE17]
Perrin, T., "The Noise Protocol Framework",
Revision 31,
2016-10-07
http://noiseprotocol.org/noise.pdf

[ARQ17]
Bada, A., "Automatic Repeat Request (Arq) Protocols",
Volume 6, Issue 5 of The International Journal of Engineering and Science,
2017,
http://www.theijes.com/paper/vol6-issue5/J0605016466.pdf

[RSFBLUE]
Zhang, C., Yin, J., Cai, Z., "RSFB: a Resilient Stochastic
Fair Blue algorithmagainst spoofing DDoS attacks", December 2009,
https://sites.google.com/site/cwzhangres/home/files/RSFBaResilientStochasticFairBluealgorithmagainstspoofingDDoSattacks.pdf

[SFBLUE]
Feng, W., Kandlur, D., Saha, D., Shin. K.,
"Stochastic Fair Blue: A Queue Management Alogirthm
for Enforcing Fairness", 2001,
http://www.thefengs.com/wuchang/blue/41_2.PDF

[CODEL17]
Nichols, K., Jacobson, V., McGregor, A., Iyengar, J.,
"Controlled Delay Active Queue Management", March 2017,
https://tools.ietf.org/html/draft-ietf-aqm-codel-07

[RFC5404]
Eggert, L., Fairhurst, G.,
"Unicast UDP Usage Guidelines for Application Designers", November 2008,
https://www.rfc-editor.org/rfc/rfc5405.txt
