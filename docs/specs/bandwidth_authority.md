---
title: "Bandwidth Authority"
description: ""
categories: [""]
tags: [""]
author: ["David Stainton"]
version: 1
---

**Abstract**

This document describes the high level architecture and detailed
protocols and behavior required for automating the addition of 
new mix nodes to the network. This is an entirely optional
mixnet protocol that can be optionally enabled.

## 1. Introduction

The basic idea is that we have some kind of testing heuristic for validating new
mix nodes. The goal of this protocol is to cause the directory authority servers
to add the new mix nodes into it's hot spare pool. This protocol addition will
require changes to the dirauth server AND the mix node server.

### 1.1 Terminology

- `cascade` - A sequential list of mix nodes where mix node A routes only to mix node B
which routes only to mix node C. If any of the mix nodes in the cascade have an outage
then the entire cascade has an outage. This is used in the context of batch mixing
where the mixnet PKI advertises many cascade thereby providing high availability.

- `stratified topology` AND `topology layers` - Refers to the various
sections of a network which uses the `stratified topology`.
`stratified topology` imples an ordered set of disjoint subsets of mix nodes.
Every route in such a network can select *any* mix in the first topology layer to
be it's route's first hop. Likewise *any* mix in the second topology layer
can be selected for the route's second hop and so on.

- `mix` - A mix node which is used to compose a mix network.

- `continuous time mix` - A mix that does NOT participant in a batch
but instead can receive messages at any time without adhering to any
sort of schedule which dictates when it can receive a message.

- `batch mix` - A technique for mix networks that uses a fixed sized
set of message input slots and routes that precise number of messages
resulting in the same number of output message slots. Often these
types of mixing strategies can make use of verification protocols
for discovering bad acting mix nodes.

## 1.2 Changes to the Mix node behavior

The mix nodes currently do not allow any connections them unless their mix
descriptor is being advertized by the dirauth's published PKI document.
We need to add an initial "testing more" state to the mix nodes such that
they can be started up without relying on the dirauths and without submitting
their mix descriptors to the dirauths. Testing mode should cause the mix node
to allow at specific set of bandwidth authorities servers to make a PQ Noise
protocol connection, and route Sphinx packets. Using this mechanism, two or
more bandwidth authorities servers will conduct a bandwidth test of the new
mix node.

## 1.3 Changes to the Directory Authority behavior

There may be some advantages in collecting new mix nodes in an unused
hot spare pool rather than immediately adding them to the mix network.
In any mixing strategy including continusou time mixing or even in batch mixing,
adding as many mixes as possible to the network is a very bad idea because
it would reduce the entropy on the network which reduces traffic analysis
resistance and privacy properties.

In the context of a continuous time mixing strategy we'd want to only add
new mixes when the entropy falls below a certain threshold.
We currently have not established a tuning methodlogy and therefore we
cannot possibly establish a entropy threshold for this purpose without
first tuning the mix network. That having been said we can in the interim
make some estimates.

In a batch mixing context where the dirauth's PKI document is advertising
many mix cascades, we'd only add new cascades if the current set of cascades
are getting a certain ratio of message slots filled every round on average.
For example perhaps if they get 80% or 90% of their message slots filled
every round then it's time to add more cascades. Everything about tuning
batch mix networks is simples than continuous time mix networks.

## 2. Threat Model

There is some tension between growing the network as fast as possible
and keeping the network secure in the sense of not having too many bad acting mix nodes.
We would ideally like to prevent a single entity from operating multiple mix nodes
in different topology layers. Without some form of absolute mix operator identity, there is
no way for us to enforce this if we are adding new mix nodes to every network topology layer.

The any trust assumption states: as long as there is one honest mix is a given route
adveraries will not be able to link a packet going into the mix network with it's
final destination. Likewise, a bad route is defined as a route where every hop
is a bad acting mix node.

Therefore, when we add many new mix nodes to the network we alter the
probability of select bad mixes and bad routes. If a given adversary is
able to place many mixes in each layer then there's an increased chance
that clients will select a bad route completely controlled by that adversary.

Likewise in a batch mixing scenario we'd want to make sure that a single entity doesn't
operate more than one mix node per cascade.

In either case, stratified topology with continuous time mixing or many cascades with
batch mixing; the solution to the above problem is to have an enforced identity system
such that the dirauth can enforce the topology rules of mix node placement.

However it is probably acceptable to ignore the above problem if there is a mechanism
to detect and remove bad mixes such as is described in this paper:

* "No right to remain silent: Isolating Malicious Mixes"
  by Hemi Leibowitz, Ania Piotrowska, George Danezis, and Amir Herzberg 
  https://eprint.iacr.org/2017/1000


We can enforce the topology rules as a sort of naive best effort
attempt to enforce our topology rules of mix node placement in the context
of a non-enforceable identity system. In that case each opeartor
would have a unique 32 byte identity tag such that when they
operatore multiple mixes, each mix descriptor would have that same tag in their
`OperatorIdentity` field:

```
// MixDescriptor is a description of a given Mix or Provider (node).
type MixDescriptor struct {
	// OperatorIdentity is a 32 byte identity value, e.g. a hash of a well known public key.
	OperatorIdentity *[32]byte

	// Name is the human readable (descriptive) node identifier.
	Name string

	// Epoch is the Epoch in which this descriptor was created
	Epoch uint64

	// IdentityKey is the node's identity (signing) key.
	IdentityKey sign.PublicKey

	// Signature is the raw cert.Signature over the serialized MixDescriptor
	Signature *cert.Signature `cbor:"-"`

	// LinkKey is the node's wire protocol public key.
	LinkKey wire.PublicKey

	// MixKeys is a map of epochs to Sphinx keys.
	MixKeys map[uint64][]byte

	// Addresses is the map of transport to address combinations that can
	// be used to reach the node.
	Addresses map[Transport][]string

	// Kaetzchen is the map of provider autoresponder agents by capability
	// to parameters.
	Kaetzchen map[string]map[string]interface{} `cbor:"omitempty"`

	// Provider indicates that this Mix is a Provider
	Provider bool

	// LoadWeight is the node's load balancing weight (unused).
	LoadWeight uint8

	// AuthenticationType is the authentication mechanism required
	AuthenticationType string

	// Version uniquely identifies the descriptor format as being for the
	// specified version so that it can be rejected if the format changes.
	Version string
}
```

## 3. Protocol Description

The mix node will essentially have an added section to it's finite state machine
where is participate in the bandwidth authority protocol and then awaits
approval or rejection from the dir auths:

1. boot up in "test mode" and contact ALL the dirauths, "Hi! I want to be part of your network."
1. await bandwidth authority probes
3. await confirmation/rejection from the dirauths before switiching to "production mode"
4. Switch "production mode"; upload mix descriptors to the dirauths and obey their
published PKI document and it's placement of your mix in the topology or hotspare pool.


With the above design, the new mix node informs the dirauths that they wish to be added to the network.
The dirauths therefore need an additional finite state machine to handle this:

1. listen for new node registration requests
2. when a request is receives, delegate the bandwidth testing to several bandwidth authorities
3. await bandwidth authority probe statistics
4. based on the stats, decide whether to aprove or reject the new mix registration
5. if approved, add the mix to the mix hotspare pool
6. send approval/rejection message to new mix node

Currently the PKI epoch duration is 20 minutes. Therefore new mix node registrations will take at least
20 minutes. In the above protocol description, ideally every dirauth node knows about the new mix
node registration request. Thus each dirauth can assign it's own bandwidth authority node to probe
the new mix node. Each will likewise in turn report it's statistics to the dirauth that requested
it's service. The consensus (aka voting) protocol will then make use of the set of approvals/rejections
for each of the new mix node registrations within the epoch boundary. Therefore if a majoriy of dirauths
approve of a mix registration then that mix node will be added to the dirauth hot spare pool.


