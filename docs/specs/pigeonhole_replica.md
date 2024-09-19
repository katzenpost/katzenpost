---
title: "Pigeonhole Replica Specification"
description: ""
categories: [""]
tags: [""]
author: ["David Stainton"]
version: 1
---

**Abstract**

This document describes the design details of the Pigeohole storage replica.


## Design

Like all Katzenpost components we will implement the Pigeonhole replicas in golang.
However Boltdb is not ideal for the persistent storage, we instead select [Rocks DB](https://rocksdb.org/).
According to my brief research this seems to be the best golang wrapper for RocksDB:
[grocksdb](https://github.com/linxGnu/grocksdb)

### PQ Noise wire protocol

Replicas communicate with each other directly over the Internet instead of using our mixnet.
However they will use our PQ Noise based wire protocol on top of either TCP or QUIC.
We are in a sense composing a new wire protocol for the replicas with these properties:

* padded to a new max size in both directions
* constant time sending/receiving messages
* restrict the commands used to just the few (one?) needed for this protocol

**TODO**: need to add the PQ Noise protocol commands here.

### Replica envelopes


**write request**:

1. sender’s ephemeral public key
2. envelope DEK encrypted with shared secret between sender private key and replica public key
3. enveloped message, encrypted with DEK, containing a BACAP message.

```golang

type WriteRequest struct {
	SenderEPubKey []byte
	DEK *[32]byte
	Ciphertext []byte
}
```

**BACAP message**:

1. BACAP box ID M_ctx_i
2. BACAP payload c_ctx_i
3. BACAP signature s_ctx_i

```golang

type BACAPMessage struct {
	ID *[32]byte
	Payload []byte
	Signature []byte
}
```

**read request**:

1. sender’s ephemeral public key
2. envelope DEK encrypted with shared secret between sender private key and replica public key
3. enveloped message, encrypted with DEK, containing a BACAP box ID:
 * BACAP box ID M_ctx_i

```golang

type ReadRequest struct {
	SenderEPubKey []byte
	DEK *[32]byte
	Ciphertext []byte
}
```


