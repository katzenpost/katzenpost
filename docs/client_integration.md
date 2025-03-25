---
title: "Katzenpost Client Integration Guide"
linkTitle: ""
description: ""
categories: [""]
tags: [""]
author: []
version: 0
draft: false
---


## Overview

This guide is intended to help developers use a Katzenpost mixnet
in their software project. The Katzenpost client daemon is designed to
multiplex connections from multiple applications on the same device.
In this guide we do not cover how to make new mixnet services, only
how to talk to them over the mixnet.

Your mixnet applications will use a thin client library to talk to the
client daemon. It's a simple protocol where clients send and receive
CBOR encoded length prefixed blobs. All of the cryptographic and
network complexities are handled by the daemon so that applications
don't need to.

Our thin client protocol is described here:

https://katzenpost.network/docs/specs/connector.html

It can in theory be used by any language that has a CBOR serialization
library and can talk over TCP or UNIX domain socket. Currently there
are three thin client libraries:

* golang reference thin client source code:
  https://github.com/katzenpost/katzenpost/tree/main/client2
  golang thin client API docs:
  https://pkg.go.dev/github.com/katzenpost/katzenpost@v0.0.46/client2/thin

* rust thin client source code:
  https://github.com/katzenpost/thin_client/blob/main/src/lib.rs

* python thin client source code:
  https://github.com/katzenpost/thin_client/blob/main/thinclient/__init__.py
  


## Thin client configuration

In principle thin client configuration need only have
two sections:

1. Callbacks for handling received events.
2. Sphinx Geometry for determining the maximum size
   of usable payload in a Sphinx packet.

NOTE: currently only the golang thin client has the Sphinx geometry in it's configuration.
The other implementations are configured with only callbacks.


The only use the thin client or application would have for the Sphinx geometry is to
learn the application's maximum payload capacity which is not the same as the Sphinx packet
payload size because of the SURB which is stored in the payload so that a reply can be
received.



## Getting the PKI document

You'll need a view of the mix network in order to send packets. The
PKI (public key infrastructure) document is published by the mix
netowrk's set of directory authorities. Our design is directly
inspired by Tor and mixminion but we don't need to discuss the details
here except to say that there's some fixed time unit known as the
Epoch, and every Epoch has an exclusive PKI document associated with
it. As a client you need to be able to gather PKI documents for each
epoch that your packets will be used in. This is important for our
Sphinx based routing protocol because the mix keys used for the mix
node's Sphinx packet decryption are used only for for Epoch and then
they expire. Our PKI document publishes several Epochs worth of future
mix keys so that the upcoming Epoch boundary will not cause any
transmission failures.

Now that we've gotten that introduction out of the way, I will tell
you that as an application developer using the thin client, I mainly
care about the mixnet services that I can learn from the PKI document.
For example our mixnet ping CLI tool gets a random echo service from the
PKI document and the it handles it's business using that information:

```golang
	thin := thin.NewThinClient(cfg)
	err = thin.Dial()
	if err != nil {
		panic(err)
	}

	desc, err := thin.GetService("echo")
	if err != nil {
		panic(err)
	}

	sendPings(thin, desc, count, concurrency, printDiff)
```

The `GetService` is a convenient helper method which searches
the PKI document for the the service name we give it and then
selects a random entry from that set. I don't care which XYZ
service I talk to just so long as I can talk to one of them.

The result is that you procure a destination mix identity hash
and a destination queue ID so that the mix node routes the message to the service.

The hash algorithm used is provided by "github.com/katzenpost/hpqc" ("golang.org/x/crypto/blake2b.Sum256")

```golang
func Sum256(data []byte) [blake2b.Size256]byte {}
```

For example:

```golang
    import (
        "github.com/katzenpost/hpqc/hash"
        "github.com/katzenpost/katzenpost/thin"
    )

	thin := thin.NewThinClient(cfg)
	err = thin.Dial()
	if err != nil {
		panic(err)
	}

	desc, err := thin.GetService("echo")
	if err != nil {
		panic(err)
	}
    serviceIdHash := hash.Sum256(desc.MixDescriptor.IdentityKey)
    serviceQueueID := desc.RecipientQueueID
```

## Sending a message

Each send operation that a thin client can do requires you to specify
the payload to be sent and the destination mix node identity hash and
the destination recipient queue identity.

The API by design lets you specify either a SURB ID or a message ID
for the sent message depending on if it's using an ARQ to send reliably or not.
This implies that the application using the thin client must do it's own book keeping
to keep track of which replies and their associated identities.

In the golang thin client, `SendMessageWithoutReply` is the simplest to use
because it takes only three arguments:

```golang
// SendMessageWithoutReply sends a message encapsulated in a Sphinx packet, without any SURB.
// No reply will be possible.
func (t *ThinClient) SendMessageWithoutReply(payload []byte, destNode *[32]byte, destQueue []byte) error
```

This method send a Sphinx packet encapsulating the given payload and
sends it to the given destination. No SURB is sent. No reply can ever
be received. This is a one way message.

The rest of the message sending methods of the thin client are variations of this basic send
but with some more complexity added for example you can choose to send a message with or without the
help of an ARQ error correciton scheme where retransmissions are automatically sent when the other party
doesn't receive you message. Or keep it minimal and send a message with a SURB
in the payload so that the service can send you a reply. Also as a convenience our golang API
has blocking and non-blocking method calls for these operations.

The rust and python thin client APIs are very similar. Knowledge of
one is easily transferrably to another implementation.



## Receiving events and messages

It's worth noting that our golang thin client implementation gives you an events channel for
receiving events from the client daemon. Whereas the Python and Rust thin clients allow you to
specify call backs for each event type. Both are equivalent to each other.


In golang, use the method EventSink() to return a channel of type thin.Event.
```golang
	thin := thin.NewThinClient(cfg)
	err = thin.Dial()
	if err != nil {
		panic(err)
	}

    eventCh := thin.EventSink()
    for ev := range eventCh {
        switch ev.(type) {
            case *thin.NewDocumentEvent:
            // handle event
            default:
        }
    }
```

### Thin client events

Here I'll tell you a bit about each of the events that thin clients receive:

* ShutdownEvent: This event tells your application that the Katzenpost
  client daemon is shutting down.

* ConnectionStatusEvent: This event notifies your app of a network
  connectvity status change, which is either connected or not
  connected.

* NewPKIDocumentEvent: This event tells encapsulates the new PKI
  document, a view of the network, including a list of network
  services.

* MessageSentEvent: This event tells your app that it's message was
  successfully sent to a gateway node on the mix network.

* MessageReplyEvent: This event encapsulates a reply from a service on
  the mixnet.

* MessageIDGarbageCollected: This event is an ARQ garbage collecton
  event which is used to notify clients so that they can clean up
  their ARQ specific book keeping, if any.



## Conclusion

This is a guide to performing very low level and basic interactions with mixnet services.
Send a message to a mixnet service and receive a reply. Very basic but also a powerful building block.

In the future we plan on:

* writing various messaging systems and making their client controls exposed to the thin client

* writing higher level protocol additions to this thin client API
that would allow clients to send and receive streams of data. Streaming data is useful
for a variety of applications where strict datagrams may not be as easily useful.

