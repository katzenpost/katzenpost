---
title: "Propagation of Mix Decoy Loop Statistics"
description: ""
categories: [""]
tags: [""]
author: ["David Stainton"]
version: 1
---

**Abstract**

This document describes various protocols which will be used to communicate 
statistics to mix network clients which tells them about the packetloss
on each mix node. In the context of continuous time mixing stategies such
as the memoryless mix used by Katzenpost, n-1 attacks may use strategic
packetloss. Determining whether or not it's an n-1 attack is outside the scope
of this work.

## 1. Design Overview

Clients should combine their own decoy loop statistics with those from all the mix
nodes in order to make better decisions about how to compose their Sphinx packet routes.
At the beginning of each epoch, all mix nodes send their statistics to a randomly selected
Provder about the previous epoch; however this sending of statistics must be randomly staggered.

All Providers would run a mixnet service which accepts signed payloads from any of the mix nodes.
Each mix node only has to upload their statistics to one randomly selected Provider. All Providers
would eventually update each other via a gossip protocol which does not use the mix network.

The non-mixnet gossip protocol would require another socket listener on each protocol and a few
protocol commands added to our PQ Noise based `wire protocol`. The listener would only allow connections
from other Providers on the network. The gossip protocol would rapidly propagate all the statistics.

Clients directly connected to a given Provider would use a new `wire protocol` command to retrieve
the mix decoy loop stats.

### 1.2 Terminology

- `wire protocol` - refers to our PQ Noise based protocol which currently uses TCP but in the
future will optionally use QUIC. This protocol has messages known as wire protocol `commands`, which are
used for various mixnet functions such as sending or retrieving a message, dirauth voting etc.

- `Providers` - refers to a set of node on the edge of the network which have two roles,
handle incoming client connections and run mixnet services. Soon we should get rid of `Providers`
and replace it with two different sets, `gateway nodes` and `service nodes`.

- `Epoch` - The Katzenpost epoch is currently set to a 20 minute duration. Each new epoch
there is a new PKI document published containing public key material that will only 
be valid for that epoch.


## 2. Mix Behavior

Our current implementation involves ignoring the replies to these mix originating decoy loops.
Instead of ignoring them, we want to keep track of all the loops successfully sent AND
all the loops that were NOT successful. We might as well note the time sent as well.
The book keeping is essentially two lists of paths through the network and the times sent.

Mix nodes have no need to store this information once it's sent to the Providers. However mix nodes
will need to store the previous epoch's decoy loop statistics while at the same time they are
collecting statistics for the new epoch. Therefore it makes sense to have a hashmap from epoch
IDs to mix decoy stats. Some simple heuristic for garbage collection is probably good enough,
such as, remove the previous epoch's stats once they've been sent to at least three Providers.

There's some minimum Sphinx payload size that can accommodate a given mix decoy loop rate of send
and we should make sure we're within those bounds when changing Sphinx payload size or the
decoy rate.

## 3. Provider Service

A built-in Provider service can be enabled by default on all Providers so that they can
receive mix node decoy loop statistics. If need be the dirauths can enforce that ALL
Providers need to have this service enabled.

Perhaps it should be known as the `decoy stats caching service`.

## 4. Decoy Stats Cache Retrieval

Clients or any of the other Providers may retrieve a given Provider's cache via the new
wire protocol command:

```
type GetLoopDecoyStats struct {
	Epoch uint64
}
```

Where the corresponding response is:

```
type GetLoopDecoyStatsResponse struct {
	Epoch uint64
	Payload []byte
}
```

The payload will be a CBOR encoded struct of type:

```
type LoopStats struct {
	Epoch uint64
	Stats []*LoopStat
}

type LoopStat struct {
	forwardPath []*sphinx.PathHop
	replyPath   []*sphinx.PathHop
	sentTime    time.Time
	isSuccess   bool
}
```

The above `LoopStats` MUST be signed by the mix, and so,
we marshal it into this type with a signature field:

```
type SignedLoopStats {
	Payload: []byte,
	Signature: []byte,
}
```

Currently, all Katzenpost components, mix nodes, dirauth servers and clients all use
our hybrid Sphincs+ Ed25519 signature scheme for verifying mix descriptors and PKI documents.
This works well enough despite the 49 kilobyte signature size because the signature never
transit the mixnet itself, there are merely sent over our PQ Noise based wire protocol.
However for these statistics, we'll be sending them over the mixnet to the Providers.
Therefore we'll use a different hybrid signature scheme with a smaller signature size
that will easily fit within our Sphinx packet payload size.

Perhaps use: ed25519 + Dilithium


## 5. Gossip Protocol

### 5.1 Provider wire auth

The gossip protocol makes use of the above defined wire protocol commands, `GetLoopDecoyStats`
and `GetLoopDecoyStatsResponse`. One of the requisite changes is to specifically allow
Providers to connect to one another via our wire protocol authentication. This should happen
on a separate listener so that it only allows our restricted set of commands, just the two mentioned.

### 5.2 Gossip Protocol Propagation Heuristics and Parameterizations

At this time I have not yet researched gossip protocol designs. I imagine a naive implementation
might be good enought to start out; such as, each Provider sends it's cache to three random Providers
whenever it gets an update.
