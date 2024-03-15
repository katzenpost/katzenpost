---
title: "Propagation of Mix Decoy Loop Statistics"
description: ""
categories: [""]
tags: [""]
author: ["David Stainton", "Eva Infeld"]
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



### 1.2 Cryptographic primitives

For our cryptographic signature scheme we have chosen the hybrid post
quantum signature scheme with the smallest signature size,
`Ed25519-Dilithium2`.

### 1.3 Terminology

- `wire protocol` - refers to our PQ Noise based protocol which currently uses TCP but in the
near future will optionally use QUIC. This protocol has messages known as wire protocol `commands`, which are
used for various mixnet functions such as sending or retrieving a message, dirauth voting etc.
For more information, please see our design doc: [wire protocol specification](https://github.com/katzenpost/katzenpost/blob/main/docs/specs/wire-protocol.md)

- `Providers` - refers to a set of node on the edge of the network which have two roles,
handle incoming client connections and run mixnet services. Soon we should get rid of `Providers`
and replace it with two different sets, `gateway nodes` and `service nodes`.

- `Epoch` - The Katzenpost epoch is currently set to a 20 minute duration. Each new epoch
there is a new PKI document published containing public key material that will only 
be valid for that epoch.



## 2. Tracking Packet Loss and Detecting Faulty Mixes

Katzenpost lets different elements in the network track whether other
elements are functioning correctly.  A node A will do this by sending
packets in randomly generated loops through the network, and tracking
whether the loop comes back or not. When it comes back, it will mark
that as evidence, that the nodes on the path of that loop are
functioning correctly.

Experimental setup, node A:

* Data: each mix node collects a record of emitted test loops in a certain epoch, their paths and whether
they returned or not. Importantly, each loop is the same length and includes l steps.
* Track them in two arrays, `totalA` and `completedA`, where every slot in the array corresponds to another
node in the network.
* Every time the node A sends out a test loop, for each step in the loop, it will increment the slot
corresponding to that node by 1 in the array `totalA`.
* When a test loop returns, for each step in the loop, it will increment the slot corresponding to that
node by 1 in the array completedA.
* A decision needs to be made if it is preferable to pause sending out new loops near the end of the
epoch in order to not have false negatives.
* Generate a new array `lossA[i] = totalA[i] − completedA[i]`
* Finally, use the array totalA to normalize the entries in `lossA`, by dividing `lossA[i]/totalA[i]` for each
entry, and record the results in a new array ratiosA.
* Plot the resulting distribution, and calculate the standard deviation to detect anomalies. Have the
node report significant anomalies after a sufficient time period as to not leak information on the route
of individual loops.

You would expect the distribution of values in `totalA` to approximate a
binomial distribution. In an absence of faulty nodes, lossA should be
0, and when there are some faulty nodes values at faulty nodes should
approach 1 (if the node doesn’t work at all), and be binomially
dstributed at nodes that can share a loop with faulty nodes.

These ratio heat maps will be cryptographically signed by the mix node
that generated them before being sent to the Service nodes for
propagation via the gossip protocol detailed in the sections below.



## 3. Provider Service

The Service Nodes will receive the mix decoy loop ratios heat map
statistics via mixnet transmission of Sphinx packets to a new built-in
service. Like the echo service it will run by default without anyway
to disable it except by modifying the software.  The new services
known as "stats" has one purpose which is to cache the mix decoy loop
statistics.  These cached statistics are made available for retreival
by mixnet clients with the addition of a couple new wire protocol
commands detailed in the next section.

Mix nodes send the statistics in a CBOR encoded struct of type:

```
type SphinxLoopStats struct {
	MixIdentityHash *[32]byte
	Payload         []byte
	Signature       []byte
}
```

Our chosen cryptographic signature scheme is used to sign the payload which is the following
CBOR encoded struct type:

```
type LoopStats struct {
	Epoch           uint64
	MixIdentityHash *[32]byte
	Ratios          map[[32]byte]float64
}
```

which represent's one mix node's computed ratios heat map for the entire network.
The `LoopStats` struct AND the cryptographic signature are stored as the `CacheEntry` struct type:

```
type CacheEntry struct {
	LoopStats *LoopStats
	Signature []byte
}
```


## 4. Decoy Stats Cache Retrieval

Clients or any of the other Providers may retrieve a given Provider's cache via the new
wire protocol command:

```
type GetDecoyLoopsCache struct {
	Epoch uint64
}
```

Where the corresponding response is:

```
type DecoyLoopsCache struct {
	Payload []byte
}
```

The `Payload` is a CBOR encoded struct of type:

```
type AllHeatMaps struct {
	Nodes map[[32]byte]*CacheEntry // mix id -> cache entry
}
```
Here we are mapping from the 32 byte hash of the mix identity public key to the `CacheEntry`.
The correct behavior for any network entity receiving an `AllHeatMaps` struct is to
iterate over all the keys and value sin the `Nodes` mapping and marshal each CacheEntry's
`LoopStats` into a CBOR binary blob AND then verify the signature against this blob using
the public decoy loop cache signing key from the latest PKI document's mix descriptor.
Which mix descriptor do we get this public key to verify the signature? The mix node with the
same mix ID as the key in the `Nodes` map.



## 5. Gossip Protocol

The gossip protocol listener will be a new listener seperate from the
rest of the mixnet activity and it will run on the Service Nodes and
on Gateway Nodes. Currently these two sets of nodes are treated as one
set known as Providers.



### 5.1 Protocol Description

The gossip protocol is a lossy best effort protocol. This means no retransmissions.
We make use of only one `DecoyLoopsCache` wire protocol command for sending
caches between nodes.

The protocol has two rounds:

* Round 1. Every mix node generates the ratios heat map statistics and then picks 3 Providers at random,
sends them the report.

* Round 2. Every provider sends everything it's got to all
other providers. This has a lot of connections between providers but
is very resistant to malicious ones.



### 5.2 Wire Authentication

We can accomplish the above with help from our PQ Noise authentication.
What we mean is that the above two "Rounds" can be coded as two different
behaviors of the Provider nodes based on the identity of the node sending to them.

We know from our understanding of `Round 2` that if a Provider receives a cache report
from another Provider that it should simply add the cache to it's records and return to the idle state.

However in `Round 1` the Provider authenticates the wire protocol connection from the mix node
and this signals to our Provider the alternative behavior where it caches the reports and wait a
little while before transitioning to `Round 2` and sending all reports to all nodes.



# 6. Security and Privacy Considerations



# 7. Future improvements



# 8. Conclusions
