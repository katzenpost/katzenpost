

---
title: "Katzenpost mixnet Reunion protocol variation"
description: ""
categories: [""]
tags: [""]
author: ["David Stainton"]
version: 0
---

**Abstract**

This document defines just the Katzenpost spefic details of the
Reunion protocol variation and does not specify the Reunion protocol
itself.


## 1. Introduction

For our first simplest iteration, we'll start out with the protocol
being bounded by the Epoch whose current duration is set to 20 minutes
operated by a SPOF service on the Katzenpost mixnet. Later we can
remove the SPOF and span multiple Epochs with some clever tweaks.


## 2. Design

We pick a fixed size payload for Reunion T1 messages: 3500 bytes.

Here's the rationale:

The public keys size for the hybrid scheme NIKE CTIDH-2048_X25519,
is 32 + 256 = 288 however our old NIKE double ratchet exchanges two public
keys in the exchange message thus requiring 288 * 2 = 576 bytes.
Previously the payload size was set to 1000 bytes. However we should probably
set the payload to at least 2000 bytes given that ML-KEM-1024 public key is 1568 bytes.
ML-KEM-1024's ciphertext length is also 1568 bytes. 1568 * 2 = 3136 

Therefore our Reunion message sizes are:

* T1 message size: 32 + 128 + 16 + 3500 = 3676
* T2 message size: 32
* T3 message size: 32
 
These however are not suitable to sending over the network without
additional fields to indicate to the Reunion server how they should be stored.


## 3. Client Message format

Here we specify the Katzenpost specific messages that a reunion client
sends to the Reunion service. The `Payload` fields store the actual
Reunion messages, T1, T2 or T3 and the other fields indicate to the Reunion
service how these opaque blobs should be stored.


```golang
// SendT1 command is used by clients to send their T1 message to the Reunion DB.
type SendT1 struct {
    // Epoch specifies the current Reunion epoch.
    Epoch uint64

    // Payload contains the T1 message, fixed size.
    Payload []byte
}
```

```golang
// SendT2 command is used by clients to send their T2 message to the Reunion DB.
type SendT2 struct {
    // Epoch specifies the current Reunion epoch.
    Epoch uint64

    // SrcT1Hash is the hash of the T1 message sent by this sender.
    SrcT1Hash [32]byte

    // DstT1Hash is the hash of the T1 message which this T2 message is replying.
    DstT1Hash [32]byte

    // Payload contains the T2 message.
    Payload []byte
}
```

```golang
// SendT3 command is used by clients to send their T3 message to the Reunion DB.
type SendT3 struct {
    // Epoch specifies the current Reunion epoch.
    Epoch uint64

    // SrcT1Hash is the hash of the T1 message sent by this sender.
    SrcT1Hash [32]byte

    // DstT1Hash is the hash of the T1 message which this T2 message is replying.
    DstT1Hash [32]byte

    // Payload contains the T3 message.
    Payload []byte
}
```


## 4. Reunion Service design

To be clear, the reunion service knows nothing except that it should
store and retrieve opaque binary blobs. It should index these storage
buckets by the Epoch id... and this also helps us with our garbage
collection scheme where we can confidently purge storage buckets
associated with Epochs older than currentEpoch - n where n is some
reasonably small value like 3 or 4.


Our Reunion server's opaque blob storage indexes by Epoch ID at the top level, `ReunionStates` object:

```golang

// ReunionStates is a type encapsulating sync.Map of uint64 -> *ReunionState.
type ReunionStates struct {
    states *sync.Map // uint64 -> *ReunionState
}

// ReunionState is the state of the Reunion DB.
// This is the type which is fetched by the FetchState
// command.
type ReunionState struct {
    // t1Map is a slice of the SendT1 command received from a client.
    t1Map *sync.Map

    // messageMap maps the destination t1 hash to a linked list containing
    // t2 and t3 messages, the LockedList defined above.
    messageMap *sync.Map
}
```






