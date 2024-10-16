---
title: "Pigeonhole Replica Specification"
description: ""
categories: [""]
tags: [""]
author: ["David Stainton", "thethreebithacker"]
version: 1
---

**Abstract**

This document describes the design details of the Pigeohole storage replica.


## Design

Like all Katzenpost components we will implement the Pigeonhole replicas in golang.
However Boltdb is not ideal for the persistent storage, we instead select [Rocks DB](https://rocksdb.org/).
According to my brief research this seems to be the best golang wrapper for RocksDB:
[grocksdb](https://github.com/linxGnu/grocksdb)

## Replica envelopes

The inner envelope payload contains a command which either causes the storage replica to perform read or write request:

```golang
type ReplicaRead struct {
  ID *[32]byte
}

type ReplicaWrite struct {
	ID *[32]byte
	Payload []byte
	Signature []byte
}
```

These commands, `ReplicaRead` and `ReplicaWrite` are encrypted and encapsulated within the `ReplicaMessage`:

```golang
type ReplicaMessage struct {
	ReplicaID uint8
	SenderEPubKey []byte
	DEK []*[32]byte
	Ciphertext []byte
}
```

The above fields are:
* `ReplicaID`: a unique identity indicating a specific storage replica
* `SenderEPubKey`: sender’s ephemeral public key
* `DEK`: envelope DEK encrypted with shared secret between sender private key and replica public key
* `Ciphertext`: enveloped message, encrypted with DEK, containing a BACAP message.

Therefore `ReplicaRead` and `ReplicaWrite` commands are exchanged end
to end between client and storage replicas and storage courier
services never get to read them. The courier services only see opaque
ciphertext from the `ReplicaMessage`s.

Our entire MKEM based protocol works like this:

```golang
func TestMKEMProtocol(t *testing.T) {
	nikeName := "x25519"
	nike := schemes.ByName(nikeName)
	s := FromNIKE(nike)

	// replicas create their keys and publish them
	replica1pub, replica1priv, err := s.GenerateKeyPair()
	require.NoError(t, err)
	replica2pub, _, err := s.GenerateKeyPair()
	require.NoError(t, err)

	// client to replica
	request := make([]byte, 32)
	_, err = rand.Reader.Read(request)
	require.NoError(t, err)
	privKey1, envelopeRaw := s.Encapsulate([]*PublicKey{replica1pub, replica2pub}, request)
	envelope1, err := CiphertextFromBytes(s, envelopeRaw)
	require.NoError(t, err)

	// replica decrypts message from client
	request1, err := s.Decapsulate(replica1priv, envelopeRaw)
	require.NoError(t, err)
	require.Equal(t, request1, request)
	replyPayload := []byte("hello")
	reply1 := s.EnvelopeReply(replica1priv, envelope1.EphemeralPublicKey, replyPayload)

	// client decrypts reply from replica
	plaintext, err := s.DecryptEnvelope(privKey1, replica1pub, reply1)
	require.NoError(t, err)

	require.Equal(t, replyPayload, plaintext)
}
```

## PQ Noise wire protocol

Replicas communicate with each other directly over the Internet
instead of using our mixnet. However they will use our PQ Noise based
wire protocol on top of either TCP or QUIC. We are in a sense
composing a new wire protocol for the replicas with these properties:

* padded to a new max size in both directions
* constant time sending/receiving messages
* restrict the commands used to just the one needed for this protocol

Our PQ Noise based authentication will only allow mixnet service nodes
or other storage replicas to connect. This should prevent clients
from directly connecting to storage replicas.

Client to Storage Replica communicate via the Courier service
intermediaries and always use the `ReplicaMessage` wire command. However
Storage Replicas communicate with one another via the `ReplicaWrite`
and `ReplicaRead` wire commands.


## Courier Service

The Courier services will run as a normal service node plugin
and will be advertized in that service node's descriptor which
can be viewed by anyone with access to PKI documents.


## Katzenpost dirauth changes

The dirauth will have an additional optional configuration field(s),
the `StorageReplicas`:

```golang
// Config is the top level authority configuration.
type Config struct {
	Server      *Server
	Authorities []*Authority
	Logging     *Logging
	Parameters  *Parameters
	Debug       *Debug

	Mixes           []*Node
	GatewayNodes    []*Node
	ServiceNodes    []*Node
	StorageReplicas []*Node
	Topology        *Topology

	SphinxGeometry *geo.Geometry
}
```

Therefore in the above `Config` all nodes are defined the same:

```golang
// Node is an authority mix node or provider entry.
type Node struct {
	// Identifier is the human readable node identifier, to be set iff
	// the node is a Provider.
	Identifier string

	// IdentityPublicKeyPem is the node's public signing key also known
	// as the identity key.
	IdentityPublicKeyPem string
}
```

Our PKI document will contain an additional field, a list of
replica descriptors within the PKI document, they are also optional
and are defined as the following:


```golang
type ReplicaDescriptor struct {
        // Name is the unique name of the pigeonhole storage replica.
        Name string

        // Epoch ID
        Epoch uint64
		  
        // IdentityKey is the node's identity (signing) key.
        IdentityKey []byte
  
        // LinkKey is our PQ Noise Public Key.
        LinkKey []byte

        // EnvelopeKey is the Public NIKE Key used with our MKEM scheme.
        EnvelopeKey []byte
  
        // Addresses is the map of transport to address combinations that can
        // be used to reach the node.
        Addresses map[string][]string
}
```

We'd like to make all these changes to the dirauth such that the
additions are merely optional; and it should remain possible to
operate a Katzenpost mixnet without any Storage Replicas.



## Storage Replica Behavior

Replicas learn about Courier Service Nodes from the PKI document. That is,
replicas can use our client library to connect to a random gateway
node in order to download cached copies of the PKI document and thus learn
about all the Courier Services. This information is useful for Storage
Replica PQ Noise authentication.

Storage replicas MUST periodically rotate their NIKE storage
keys. This rotation should be done less frequently than mix key
rotation which are currently set to every 20 minutes. Let's set the
storage replica key rotation to: once per day or once per week.

Replicas must upload their `ReplicaDescriptor` (and signature) for
each epoch. However only the Epoch field needs to change unless
there's a key rotation or other fields need to change.

