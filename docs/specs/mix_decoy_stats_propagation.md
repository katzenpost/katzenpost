---
title: "Propagation of Mix Decoy Loop Statistics"
description: ""
categories: [""]
tags: [""]
author: ["David Stainton", "Eva Infeld", "Leif Ryge"]
version: 1
---



**Abstract**

In the context of continuous time mixing stategies such
as the memoryless mix used by Katzenpost, n-1 attacks may use strategic
packetloss. Nodes can also fail for benign reasons.
Determining whether or not it's an n-1 attack is outside the scope
of this work.

This document describes how we will communicate statistics from mix nodes
to mix network directory authorities which tells them about the packetloss they are
observing.

## 1. Design Overview

Nodes (mixes, gateways, and providers) need upload packet-loss statistics to the directory authorities, so that authorities can remove malfunctioning nodes from the consensus in the next epoch.

Nodes currently sign and upload a Descriptor in each epoch.

In the future, they should instead upload a "DescriptorUploadDocument" (fixme, better name) containing:
    * Descriptor
    * Stats
    * Signature

Stats contains:
    * a map from pairs-of-mixes to count-of-loops-sent
    * a map from pairs-of-mixes to count-of-loops-received

Authorities can now detect failing mixes and remove them from the next epoch, or later potentially adjust their bandwidth weights. Clients do not need nodes' stats or their signatures over their descriptor, because they are reliant on the directory authorities anyway.


### 1.2 Cryptographic primitives

For our cryptographic signature scheme we have chosen the hybrid post quantum signature scheme with the smallest signature size, `Ed25519-Dilithium2`.

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

* Data: each network node `A` collects a record of emitted test loops in a certain epoch, their paths and whether they returned or not. Importantly, each loop is the same length and includes l steps.
* A segment is defined as a possible connection from a device in the network to another, for example from a node in the layer `i` to a node in the layer `i+1`. Each loop is a sequence of such segments.
* Each node `A` will create 3 arrays with slots corresponding to valid path segments. These arrays will be `sent_loops_A`, `completed_loops_A` and `ratios_A`.
* Every time the node A sends out a test loop, for each segment in the loop path, it will increment the slot corresponding to that nodes node by 1 in the array `sent_loops_A`.
* When a test loop returns, for each step in the loop path, it will increment the slot corresponding to that node by 1 in the array `completed_loops_A`.
* A decision needs to be made if it is preferable to pause sending out new loops near the end of the epoch in order to not have false negatives.
* Generate a new map `ratios_A`. For each slot `i`, if `sent_loops_A[i]==0` set `ratios_A[i]=1`. Else `ratios_A[i] = completed_loops_A[i]/sent_loops_A[i]`
* Plot the resulting distribution, and calculate the standard deviation to detect anomalies. Have the node report significant anomalies after a sufficient time period as to not leak information on the route of individual loops.
* Anomalies may have to be discarded if the corresponding `sent_loops_A[i]` is small.

You would expect the distribution of values in `completed_loops` to approximate a binomial distribution. In an absence of faulty nodes, `ratios` should be 1, and when there are some faulty nodes values at faulty nodes should approach 0 (if the node doesn’t work at all), and be binomially distributed at nodes that can share a loop with faulty nodes.

The report is subsequently uploaded to the directory authorities, which combine the reports of individual nodes into a health status of the network and arrive at a consensus decision about the topology of the network.


## 3. Uploading Stats to Dirauths

Stats reports are uploaded along 

```
type Upload struct {
         Descriptor []byte
         StatsReport []byte
         Signature []byte
 }
```



| ---------------- epoch N ---------------- | ---------------- epoch N+1 ---------------- | ---------------- epoch N+2 ---------------- |
| ----------- UD_N+1 --------------------  | ------------ UD N+2 -----------------------  | ----------- UD N+3 -------------------------|
         | ---------------------------------XXX---------------------- |

statrs collected during the XXX period of time, that is, the time between descriptor N+1 upload and descriptor N+2 upload, are what will affect the topology choices in epoch N+2


