---
title: "Frequently Asked Questions"
linkTitle: "FAQ"
description: ""
categories: [""]
tags: [""]
author: []
version: 0
draft: false
---

## What is a mix network?

A mix network is an unreliable packet switching network which resists
traffic analysis. Mix networks can be designed to provide various
anonymity properties such as:

- sender anonymity
- receiver anonymity
- sender and receiver anonymity with respect to third party observers

## Can Katzenpost act as a drop-in TCP replacement?

No and furthermore you should not want a stream oriented interface for
interacting with a message oriented protocol. If your application is
message oriented then integration as a Katzenpost client is possible.
Client protocol libraries are currently being developed!

Although decryption mixnets are inherently unreliable and offer
unordered delivery, reliability and ordered delivery can be achieved by
the protocol library and NOT by the mix network itself. That is to say,
the mixnet client library should abstract away all the details of
retransmissions and book keeping related to ordered delivery.

## What kinds of applications can use Katzenpost?

Katzenpost can be used by various kinds of message oriented
applications. Generally these fall into two categories:

1.  peer to peer: Alice can chat with Bob over the mixnet. In this
    case there's a protocol library that let's them send and receive
    messages with a Katzenpost specific addressing sytem. In this case
    the mixnet acts as a transport for Alice and Bob\'s interactions.
2.  client to server: Alice can interact with a service that listens
    on the mixnet for mixnet messages. This means there is a client
    and a server component and they use the mixnet as a transport for
    their interaction.

What are some examples of "client to server" mixnet applications?

- Clients send URLs to a "retrieval service" on the mixnet. This  service retrieves the URLs and sends the content back to the client.
- Privacy preserving crypto currency wallet sends crypto currency transactions to the mixnet service. This service then submits the transaction to the blockchain.

What are some examples of "peer to peer" mixnet applications?

- Encrypted chat applications can use the mixnet as the transport.
- File exchange: Alice can send Bob a file using the mixnet as the transport.

## What is Loopix?

Loopix is described in the paper "The Loopix Anonymity System"
published at USENIX 2017, https://arxiv.org/pdf/1703.00536.pdf

Briefly, Loopix uses a collection of the best mix network designs to
create a messaging system that has the property of sender and receiver
anonymity with respect to third party observers. This particular
meaning of \"anonymity\" is remarkably different than what Tor
provides. Loopix does not have strong location hiding properties nor
does it provide sender anonymity or receiver anonymity. That having
been said it should be possible to create such systems based on the
Loopix design.

The Loopix design is informed by over 15 years of mixnet literature
and strives to reduce many kinds of metadata leakages that
historically have made mix networks vulnerable to long term
statistical disclosure attacks. Loopix has a defense against
blending/n-1 attacks. Loopix explores the tradeoff between decoy
traffic and latency, thus revitalizing mix networks with much lower
latency for message transportation.

Loopix uses the Sphinx cryptographic packet format, the Poisson mix
strategy, three kinds of decoy traffic and the stratified mix
topology. It\'s Provider architecture forces long term statistical
disclosure attacks to take place on the receiver\'s Provider, thus
forcing such adversaries to actively compromise Providers instead of
passively observing the mix network which is in contrast to historical
mix network designs.

## What is Katzenpost?

Katzenpost has the goal of implementing the Loopix designs with the
additional property of message transport reliability. Reliability is
achieved using a Stop and Wait ARQ which is half duplex and uses SURBs
to create the reply channel for the ACKnowledgement messages.

Why is this a big deal? To our knowledge, no other mix network design
has attempted to achieve reliability. We believe that the lack of
reliability has been one of the major obstacles to the adoption of mix
networks. "Would you want to use a messaging system which might not
even transport your messages to their destination?"

## How are mix networks different from Tor?

Tor is stream oriented. Mixnets are message oriented. Tor is low
latency, easy to use, has a great primary application (Tor Browser),
and functions as an extremely useful general purpose anonymity system.
This is in contrast to mix networks which do not function well as
general purpose anonymity systems. Instead mix networks are better
suited to customization for specific applications, for example a mix
network for instant messaging and a mix network for e-mail will have
different traffic patterns and therefore require different decoy
traffic patterns to achieve the desired traffic analysis resistant
properties.

There are also many adversarial model differences between Tor and mix
networks. For example, Tor can be easily deanonymized by statistical
correlation attacks by a sufficiently global adversary whereas mixnets
are not immediately vulnerable to these kinds of attacks if they
correctly use mix strategies and decoy traffic.

Both Tor and mix networks can scale well with respect to increasing
user traffic, however Tor requires route unpredictability to achieve
it's anonymity properties. Mix networks on the other hand do not
require route unpredictability and therefore can achieve very strong
anonymity properties with far fewer network nodes than Tor.

## How do mix networks compare to Pond?

Pond doesn't actually mix anything whereas mix networks specifically
contain component mixes, each containing a mix queue which "mixes"
messages together via some specific mix strategy before sending them
to the next hop in the route. Pond uses a group signature scheme to
prevent the server from learning to whom a message is being sent to.
Pond uses Tor onion services as it's transport while also using decoy
traffic to prevent a passive network observer from determining when a
user sends a message. Mix network designs can also use decoy traffic,
however in the Loopix design there are three different kinds of decoy
traffic that serve different purposes. Mix networks also scale much
better with respect to increasing users and traffic whereas pond
servers quickly become performance bottlenecks. This is in contrast to
mix networks where additional mixes can be added to the network in
order to efficiently process increases in user traffic.

## How does Vuvuzela differ from Loopix/Katzenpost?

Vuvuzela uses the cascade mix topology which does not scale well with
respect to an increase in user traffic. Loopix uses the stratified
topology which scales very well. In Vuvuzela, messages cannot be
received when a user is offline. In Loopix messages received while a
user is offline are queued by their Provider. Vuvuzela operates in
rounds whereas Loopix does not. Vuvuzela does not provide reliable
message transportation whereas Katzenpost does.

## How does AnonPOP differ from Loopix/Katzenpost?

AnonPOP operates in rounds and provides offline storage of messages.
Loopix uses a continuous time mix strategy so that it avoids user
synchronization issues. AnonPOP does not provide reliable message
transportation whereas Katzenpost does.
