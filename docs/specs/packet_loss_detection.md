---
title: "Packet Loss Detection"
description: ""
categories: [""]
tags: [""]
author: ["David Stainton"]
version: 1
---

**Abstract**

This document describes the high level architecture and detailed
protocols and behavior required for detection of packet loss
in the mix network.

## 1. Introduction

The goal is to assess the packet loss for every mix node in the network.
This serves two high level purposes:

1. enable clients to create more intelligent routes through the network
and avoid bad mix nodes

2. supply statistical information to a monetary staking/reward/slashing
incentivizational mechanism for the purpose of growing a large self-sustaining
mix network.

We detect packet loss on the mix network by only one mechanism: decoy loops.
However we make use of loops originating from two sources:

1. decoy loops originating from mix nodes
2. decoy loops originating from one or more clients


### 1.1 Terminology

- `Sphinx SURB` - SURB stands for Single Use Reply Block. It's essentially a delivery token
for transporting arbitrary messages across the mix network. However it does so without revealing
the destination location to the user of the SURB. It is said that SURBs enable anonymous replies.

- `decoy loop` - A decoy loop consists of two Sphinx routes through the mix network.
A forward route and a reply route. The reply route is achieved by means of Sphinx SURBs.
The forward Sphinx packet which is sent to a randomly selected `echo` service
on the network contains a SURB in it's payload. The `echo` service sends a reply back using
the SURB. These two routes form a loop.

## 2. Mix Packet Loss Statistics Aggregation

Mixes currently send decoy loops. However that statistical information is not acted upon
in the current implementation of Katzenpost as of this writing.

The idea of decoy loops to detect packet loss was first explored by this paper:

Heartbeat Trafﬁc to Counter (n-1) Attacks
Red-Green-Black Mixes
https://www.freehaven.net/anonbib/cache/danezis:wpes2003.pdf

However they suggest that the mix should stop routing messages if it detects some threshold of packet loss.
This is definitely too simplestic and not he approach we are looking for.
Instead we want each mix node to periodically send it's decoy loop packet loss statistics to the
Providers to be cached and accessible by all the network clients.

## 3. Combining all the statistical information

Client decoy loops are just as simple to implement as mix loops.

Clients will be able to learn about mix node packet loss from the
cached statistical information on each Provider AND from sending
their own decoy loops.

However in the sustainable mix network incentivization use case
we can perhaps collect client decoy loop statistics from several
clients operated by the dirauth system or some other equivalently
decentralized mixnet PKI.


## 4. Decoy Loop Statistical Analysis

My initial naive method for determining the relative packet
loss for each mix node in the network involves a simple tally system.
Since Sphinx is source routed, the sender of a decoy loop knows
the entire route, each hop in the forward and reply routes.
Therefore if a sender of a decoy loop does not receive a reply,
then they can add 1 to their tally for each of the mix nodes in the route.

Over time many such routes will be used to send decoy loops.
Some of those routes may share a specific mix node which may accumulate
a packet loss tally higher than the rest indicating a bad acting mix node.

## 5. Optional Sustainable Mixnet Via Incentivizational Mix Reward Slashing System

Each dirauth server could operate a mixnet client with which to gather decoy loop
statistics from the two sources we previously discussed above. If we're provided
we an algorithm for analyzing the statistics and providing a PASS or FAIL answer
for each mix node, then we can simply apply the dirauth voting protocol.
Likewise if the PKI is replaced by a DAO then that DAO would be required to
acted upon the statistics on time before publishing the next document.

