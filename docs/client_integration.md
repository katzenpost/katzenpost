
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

This guide is intended to help developers connect their applications and projects to a Katzenpost mixnet.

The Katzenpost client daemon - <b>kpclientd</b> - connects to the Katzenpost mixnet. It has <i>thin client</i> libraries in Go, Python and Rust, which you can integrate into your app that you want to work over Katzenpost. The client can multiplex connections to the mixnet from multiple applications on the same device. 

A <i>thin client</i> is an API interface for the client. It's a simple protocol where clients send and receive CBOR encoded length prefixed blobs. All of the cryptographic and network complexities are handled by the daemon so that applications don't need to do it. However, you should think of the client as part of the application, and remember that it's the outgoing connection from the client that has the mixnet's privacy properties.

Our thin client protocol is described here:
https://katzenpost.network/docs/specs/connector.html

It can be extended to be used by any language that has a CBOR serialization library and can talk over TCP or UNIX domain socket. Currently there are three thin client libraries:

* golang reference thin client source code:
  https://github.com/katzenpost/katzenpost/tree/main/client2
  golang thin client API docs:
  https://pkg.go.dev/github.com/katzenpost/katzenpost@v0.0.46/client2/thin

* rust thin client source code:
  https://github.com/katzenpost/thin_client/blob/main/src/lib.rs

* working rust example using thin client:
  https://github.com/katzenpost/thin_client/blob/main/examples/echo_ping.rs

* python thin client source code:
  https://github.com/katzenpost/thin_client/blob/main/thinclient/__init__.py
  
* working python examples using python thin client:
  https://github.com/katzenpost/thin_client/blob/main/examples/echo_ping.rs
  https://github.com/katzenpost/status
  https://github.com/katzenpost/worldmap


## Example: setup `kpclientd` and `thin_client` to use `namenlos` with Python

<i>namenlos</i> is a Katzenpost implementation ran by the KP team. It is our canonical example of a Katzenpost-type mixnet instance.

```
# To clone namenlos, you must authenticate
git clone git@github.com:katzenpost/namenlos.git

# To clone the rest, you do not need to authenticate
git clone https://github.com/katzenpost/katzenpost
git clone https://github.com/katzenpost/thin_client

# Build kpclientd
cd katzenpost/client2/
make makeclientdaemon
cd ../../

# Install thin_client for Python
cd thin_client
# Make a Python venv and install the Python thin_client module in the Python venv
python3 -m venv thin_client-venv
source thin_client-venv/bin/activate
pip install jinja2 matplotlib cartopy geoip2
pip install .
cd ../

# Install the config file and the daemon into
sudo cp namenlos/configs/client2.toml /usr/local/etc/namenlos.toml
sudo cp katzenpost/client2/cmd/kpclientd/kpclientd /usr/local/bin/kpclientd

# In a terminal run kpclientd with the namenlos config:
kpclientd -c /usr/local/etc/namenlos.toml

# In another terminal run the programs that interact with kpclientd's
# thin_client interface in the Python venv:
source thin_client/thin_client-venv/bin/activate

# Run ping:
python3 thin_client/examples/echo_ping.py

# Fetch the PKI document for the current consensus:
python3 thin_client/examples/fetch_pki_doc.py

# Generate a network_status.html file for the current network status:
python3 thin_client/examples/mixnet_status.py

# You will need to install GeoLite2-City_20241025/GeoLite2-City.mmdb to make
# the next command work.
#
# Generate a world map of the namenlos network:
python3 thin_client/examples/world_map.py
```

## Thin client configuration

The thin client configuration has at most two sections:

1. Callbacks for handling received events.
2. Sphinx Geometry for determining the maximum size of usable payload in a Sphinx packet.

NOTE: currently only the golang thin client has the Sphinx geometry in it's configuration. The other implementations are configured with only callbacks.

The only use the thin client or application would have for the Sphinx geometry is to learn the application's maximum payload capacity which is not the same as the Sphinx packet payload size because of the SURB which is stored in the payload so that a reply can be received.



## Getting the PKI document from your app

You'll need a view of the mix network in order to send packets. The PKI (public key infrastructure) document is published by the mix netowrk's set of directory authorities, and you fetch it from one of the gateways. This is not unlike <i>Tor</i> and <i>mixminion</i>. The PKI document updates every epoch, which currenttly is 20 minutes. 

The setup process as in the example above will fetch your first network config and PKI document so you can start interacting with the network, but you need your client to update the doc as needed. 

Using our Golang thin clinet API you can obtain a PKI document with `PKIDocument`:

```golang
/*
import (
    cpki "github.com/katzenpost/katzenpost/core/pki"
)
func (t *ThinClient) PKIDocument() *cpki.Document {}
*/
    ...
    doc := thin.PKIDocument()
    if doc == nil {
        panic("No Document")
    }
```

and similarly in our Rust thin client API:

```rust
    let doc = thin_client.pki_document().await;
```

Likewise in our Python thin client API:

```python
	doc = thin_client.pki_document()
```

When creating an app that works over a mixnet, you will need to interact with <i>mixnet services</i> that are listed in the PKI document.  For example our mixnet ping CLI tool gets a random echo service from the PKI document and the it handles its business using that information:

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

	// handle business here
```

In Rust:

```rust
let service_desc = thin_client.get_service(service_name).await?;
```

and in Python:

```python
service_descriptor = thin_client.get_service(doc, service_name)
```

The `GetService` is a convenient helper method which searches the PKI document for the the service name we give it and then selects a random entry from that set. I don't care which XYZ service I talk to just so long as I can talk to one of them.

```golang
// ServiceDescriptor describe a mixnet Gateway-side service.
type ServiceDescriptor struct {
	// RecipientQueueID is the service name or queue ID.
	RecipientQueueID []byte
	// Gateway name.
	MixDescriptor *cpki.MixDescriptor
}
```

The result is that you procure a destination mix identity hash and a destination queue ID so that the mix node routes the message to the service.

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
As a client you need to be able to gather PKI documents for each epoch that your packets will be used in. This is important for our Sphinx based routing protocol because the mix keys used for the mix node's Sphinx packet decryption are used only for for Epoch and then they expire. Our PKI document publishes several Epochs worth of future mix keys so that the upcoming Epoch boundary will not cause any transmission failures.

## Sending a message

Each send operation that a thin client can do requires you to specify the payload to be sent and the destination mix node identity hash and the destination recipient queue identity.

The API by design lets you specify either a SURB ID or a message ID for the sent message depending on if it's using an ARQ to send reliably or not. This implies that the application using the thin client must do it's own book keeping to keep track of which replies and their associated identities.

In the golang thin client, `SendMessageWithoutReply` is the simplest to use because it takes only three arguments:

```golang
// SendMessageWithoutReply sends a message encapsulated in a Sphinx packet, without any SURB.
// No reply will be possible.
func (t *ThinClient) SendMessageWithoutReply(payload []byte, destNode *[32]byte, destQueue []byte) error
```

This method send a Sphinx packet encapsulating the given payload and sends it to the given destination. No SURB is sent. No reply can ever be received. This is a one way message.

The rest of the message sending methods of the thin client are variations of this basic send but with some more complexity added for example you can choose to send a message with or without the help of an ARQ error correciton scheme where retransmissions are automatically sent when the other party doesn't receive you message. Or keep it minimal and send a message with a SURB in the payload so that the service can send you a reply. Also as a convenience our golang API has blocking and non-blocking method calls for these operations.

The rust and python thin client APIs are very similar. Knowledge of one is easily transferrably to another implementation.



## Receiving events and messages

It's worth noting that our golang thin client implementation gives you an events channel for receiving events from the client daemon. Whereas the Python and Rust thin clients allow you to
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

This is a guide to performing very low level and basic interactions with mixnet services. Send a message to a mixnet service and receive a reply. Very basic but also a powerful building block.

In the future we plan on:

* writing various messaging systems and making their client controls exposed to the thin client

* writing higher level protocol additions to this thin client API that would allow clients to send and receive streams of data. Streaming data is useful for a variety of applications where strict datagrams may not be as easily useful.
