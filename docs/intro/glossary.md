---
title: "Glossary"
linkTitle: ""
description: ""
categories: [""]
tags: [""]
author: []
version: 0
draft: false
---

## Traffic Analysis Resistance

Traffic analysis resistance means hiding traffic metadata from passive network
observers. Such metadata includes:

- message sender
- message receiver
- size of the message
- time of message transmission

## Mix

A mix is the primary component used to compose a mix network. Mixes receive
incoming messages, mix them via some specific mix strategy which incurs a delay
and then output the messages after removing one layer of encryption. Bitwise
unlinkability between input and output messages is achieved using the mix
network cryptographic packet format. Mixes can also output their own decoy
traffic which adds further entropy to the network as detailed in the Loopix
paper.

## Mixnet

Mixnet is short for mix network which is a network of `mix`. Fundamentally a mix
network is a lossy packet switching network whose primary purpose is to achieve
traffic analysis resistant properties such as location hiding, sender anonymity
etc. See our FAQ for more information.

## Node

A `Mix` or `Provider` instance.

## User

An agent controlling a `Client` of the `Katzenpost` system.

## Client

Software run by the `User` on its local device to participate in the `Mixnet`.

## Provider

In the context of Loopix/Katzenpost, a Provider is a node in the mix network
which is responsible for authenticating `Client` forwarding messages to the rest
of the mix network on behalf of `Client` and queueing messages that can later be
retrieved by `Client`

## PKI

Stands for Public Key Infrastructure. In the context of `Panoramix` is also
known as the `Mix Directory Authority service`. In `Katzenpost`, `Network
Authority` or in short `Authority` is the server responsible to provide the `Mix
Directory Authority service`.

It is explained in more detail in `pki`

## Sphinx

The Sphinx cryptographic packet format is now the defacto standard
for mix networks. The Mixminion mix network used SURBs to achieve
sender anonymity. Mixminion inspired the design of the Sphinx packet
format.

## Katzenpost

A mixnet design based on the `Loopix` research with added message transport reliability using an
`ARQ` protocol scheme.

## Panoramix

A project funded by the European Union's Horizon 2020 research and
innovation programme to research `mixnet` for voting, statistics, and messaging, running from
2015 to 2019. See [panoramix-project.eu](https://panoramix-project.eu/).

## Loopix

The Loopix mixnet design is described in the paper [\"The Loopix
Anonymity System\" published at USENIX 2017](https://arxiv.org/pdf/1703.00536.pdf). Loopix uses a
collection of the best mix network designs to create a messaging
system that has the property of sender and receiver anonymity with
respect to third party observers. Loopix uses the
`Sphinx`{.interpreted-text role="term"} cryptographic packet format,
various kinds of `decoy traffic`{.interpreted-text role="term"} and
a `stratified mix topology`{.interpreted-text role="term"}.

## ARQ

ARQ means Automatic Repeat reQuest which is a protocol scheme that
achieves reliability by means for ACKnowledgement protocol control
messages and retransmissions. This concept comes from the packet
switching network literature and is not generally associated with
mix networks. There is no other way to achieve network reliability
other than an ARQ scheme although there are many hybrid ARQ schemes
for radio communication that use forward error correction for the
purpose of performing retransmissions less frequently.

## Stop and Wait ARQ

Stop and Wait ARQ is the simplest of all the ARQ protocol schemes.
In the context of mix networks it also leaks the least amount of
information. When comparing it to TCP, Stop and Wait ARQ has a
congestion window of size one. This means that after a message is
transmitted, a second message cannot be sent until the ACK for the
first message is received. If the ACK message is not received within
a particular time duration then the message is retransmitted.


## SURB

SURB means Single Use Reply Block. SURBs are essentially a cryptographic
delivery token with a short lifetime. In the `Sphinx` packet format SURBs have
two categories of components, those used by the creator and those used by the
sender. When Alice creates a SURB, she retains a decryption token and a SURB ID.
Alice gives Bob a Sphinx header and a payload encryption token. Bob can use the
payload encryption token to encrypt his message. Bob then attaches the `Sphinx`
header to his ciphertext payload, thus forming a `Sphinx` packet which he sends
through the network. Bob cannot know the destination or route of this `Sphinx`
packet. Alice will receive the ciphertext payload and the SURB ID. She uses the
SURB ID to identify which SURB decryption token to use for the ciphertext
payload decryption.

SURBs have a short lifetime because mixes MUST rotate Sphinx routing
keys frequently as the primary method of achieving forward secrecy.
The other reason routing keys must be rotated is because each mix
retains a replay cache which stores a unique tag for each Sphinx
packet that traverses it. This replay cache can only be flushed after
a key rotation.

## Mixminion

A mix network software project whose design has been inspirational to the Katzenpost design. For more information see

- https://www.mixminion.net
