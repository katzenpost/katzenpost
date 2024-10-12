---
title: "Zcash Submission Protocol"
description: ""
categories: [""]
tags: [""]
author: ["David Stainton"]
version: 0
draft: true
---

**Abstract**

This document describes an unreliable unidirectional protocol and the
Zcash transaction submission mixnet service
[KAETZCHEN](#KAETZCHEN){.citation} which allows clients of the mix
network to anonymously write transactions to the Zcash blockchain.

## 1. Introduction

The primary use case for this protocol is to facilitate the development
of superior Zcash wallets with the highest degree of traffic analysis
resistance.

### 1.1 Terminology

`Provider` - A service operated by a third party that Clients
communicate directly with to communicate with the Mixnet. It is
responsible for Client authentication, forwarding outgoing
messages to the Mixnet, and storing incoming messages for the
Client. The Provider MUST have the ability to perform
cryptographic operations on the relayed packets.

`Kaetzchen` - A Provider-side autoresponder service as defined in [KAETZCHEN](#KAETZCHEN){.citation}.

### 1.2 Conventions Used in This Document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
[RFC2119](#RFC2119){.citation}.

# 2. System Overview

The Zcash sending wallet MUST be in possession of the cryptographic and
connection information which gives us the capability to send and receive
messages on the mix network. The Katzenpost architecture
[KATZMIXNET](#KATZMIXNET){.citation} describes the PKI as providing
a complete network view to clients.
[KATZMIXPKI](#KATZMIXPKI){.citation} This network consensus document
is used by clients to learn about the mixes and services on the network.
[KAETZCHEN](#KAETZCHEN){.citation}

Providers are mixes in the network that provide additional services. In
the Loopix and Katzenpost architecture Providers form the perimeter of
the network and therefore route all incoming connections from clients if
they pass the access control check using cryptographic authentication.
[KATZMIXWIRE](#KATZMIXWIRE){.citation}
[KATZMIXE2E](#KATZMIXE2E){.citation} Providers are also the
destination of each route and queue messages until a client retrieves
it.

In contrast, this crypto currency submission protocol does not have any
need to queue messages. Authenticating clients at the network perimeter
is a policy decision and is therefore out of scope here.

The Zcash sender composes a transaction and passes it's serialized blob
form into the protocol library. A Sphinx packet is created and is sent
over the mixnet link layer [KATZMIXWIRE](#KATZMIXWIRE){.citation} to
the entry point, the client's Provider. This Sphinx packet is routed
through the network and the Provider is the first to remove a layer of
Sphinx encryption. Once the packet arrives at it\'s destination
Provider, the Zcash transaction submission service receives the
transaction submission request.

```
.--------.        .----------.        .-------.        .-------.       .----------.
| Sender |  --->  | Provider |  --->  |  Mix  |  --->  |  Mix  |  ---> | Provider |
`--------'        `----------'        `-------'        `-------'       '----------'
```

On the "server side", the Provider receives the Sphinx packet and
decrypts it's payload and then passes the plaintext to the "Zcash
Submission Provider-side Service" module which parses the JSON blob and
submits the transaction blob to the Zcash blockchain using the zcashd
client RPC. No receipt or acknowledgement is produced. Handling any kind
of failure is out of scope.

### 2.1 Protocol Goals

Our goals include:

- Sender Unobservability:

Prevention of any network observer from learning when a client sends a
legitimate message (in this context a Zcash transaction). Clients
therefore periodically send decoy traffic AND legitimate traffic as
described in [LOOPIX](#LOOPIX){.citation} however for this
application we DO NOT NEED loop traffic of any kind, nor do we need
decoy loops since this protocol is unidirectional AND unreliable.

- Client To Transaction Unlinkability:

We desire to make it very difficult for active and passive network
adversaries to link a specific transaction to a specific client.

## 3. The Provider-side Zcash Transaction Submission Service

Kaetzchen [KAETZCHEN](#KAETZCHEN){.citation} services are a
request-response protocol API where responses are optional. In this
protocol no response is sent. The client puts their transaction blob
inside of a ZcashRequest and sends it to this service.

### 3.1 ZcashRequest Message Format

```
type zcashRequest struct {
        Version int
    Tx      string
}
```

The `Tx` field must be populated with the transaction blob in hex string
format.

### 3.2 Submission Service Behavior

The submission service uses a HTTP JSON RPC to submit transactions to
the blockchain using the `sendrawtransaction` RPC command which works
for Bitcoin as well as Zcash.
[ZCASHPAYMENTAPI](#ZCASHPAYMENTAPI){.citation}
[ZCASHINTEGRATION](#ZCASHINTEGRATION){.citation}
[BTCRPC](#BTCRPC){.citation}

Here's an example JSON blob:

```
{
  "jsonrpc": "1.0",
  "method": "sendrawtransaction",
  "params": ["030000807082c40301ee9aa1a0f1212131580f546903997eff6f2e3d3a8262b40c676dc2ba1aa7094b010000006b483045022100f3e5a20c7246545352c90971bb7e5d335d424b3ead78c1aefa95a630b0da577202203609bbadcddc7a89951636212643e57be2dbff4f718ef2b0ad9a41a9001c4b860121038d17c14225360038a5b6dfd063bfbe53a6e014c33f1f2bc6b49babe896595f7dfeffffff0200a3e111000000001976a914681a2881e0369225b353ff737d562ae5b60f6aca88acdd1b6403000000001976a91471257ac18b24ac66774f772782856fcedda5599288ac1f4d03003e4d030000",true],
  "id": 6439
}
```

Further details about this RPC command are here:

- https://bitcoin.org/en/developer-reference#sendrawtransaction

## 4. Client Behavior and Programming Interface

### 4.1 Starting and Stopping the Client

Requirements:

- PKI connection information
- PKI key material for signature verification
- optional Provider access credential

Using the above information the client ensures that it always has a
fresh PKI consensus document. The client periodically sends decoy drop
messages to randomly selected Providers as described in the Loopix paper
[LOOPIX](#LOOPIX){.citation}.

The optional Provider access credential is currently being used by the
Katzenpost system, an X25519 public key and a username are stored on the
Provider's user database. This in part is used to restrict access to
the user's mailbox stored on the Provider however in our case we either
wish to restrict access to the entire mixnet or we want an open use mix
network. This policy decision affects which information a client will
need.

## 4.2 Send Raw Transaction

1. The client checks a fresh PKI consensus document for advertized Zcash submission services. The client chooses one at random to use.
2.  Sends the raw transaction as a hex string.

## 5. Performance and Scaling Considerations

As mentioned in [KATZMIXNET](#KATZMIXNET){.citation} the mix network
should utilize the stratified topology to spread the Sphinx packet
traffic load. The mixes present at each strata are added or removed
according to the PKI. Therefore the PKI is used to close the feedback
loop for dynamically adjusting the load on the network.

The Zcash transaction submissions can also similarly be loadbalanced.
One or more Zcash submission services can be operated on the mix
network. They will all be advertized in the PKI consensus document as
mentioned in [KAETZCHEN](#KAETZCHEN){.citation}.

# 6. Anonymity Considerations

Using an entry Provider for many uses and for long periods of time
may be an unnecessary information leakage towards the operator of
that Provider. Instead it may be preferable to have an "open
mixnet" where clients can connect to any entry Provider to inject
their Sphinx packets into the network.

## 7. Security Considerations

Unlike the Katzenpost client to client protocol as described in
[KATZMIXE2E](#KATZMIXE2E){.citation}, this protocol uses a
Provider-side service [KAETZCHEN](#KAETZCHEN){.citation} and
therefore the Sphinx encryption is sufficient to protect the
confidentiality and integrity of the payload.

## 8. Future Work and Research

Compose a reliable Zcash submission protocol library where the
client checks the blockchain to see if the transaction was
successfully transmitted; using this information instead of
ACKnowledgment messages an Automatic Repeat reQuest protocol
scheme can be conceived.

Compose a semi-reliable Zcash submission protocol that uses client
decoy loops. The successful acquisition of a transaction blob by
the Zcash submission service triggers the response with a SURB
ACKnowledgement message as described in
[KATZMIXE2E](#KATZMIXE2E){.citation}. Clients periodically
send decoy traffic as client loops and these are indistinguishable
from transaction submission messages from the point of view of a
passive network observers and all network operators but the
destination Provider.

Nothing here is specific to Zcash. There could also be a Bitcoin
transaction submission service. These two transaction submission
services SHOULD be on the same mix network and thereby both
benefit from increasing each other's anonymity set size.

## Appendix A. References

### Appendix A.1 Normative References

### Appendix A.2 Informative References

[BTCRPC]{#BTCRPC .citation-label}
https://bitcoin.org/en/developer-reference#rpc-quick-reference

[KAETZCHEN]{#KAETZCHEN .citation-label}
Angel, Y., Kaneko, K., Stainton, D.,
"Katzenpost Provider-side Autoresponder",
January 2018,
https://github.com/katzenpost/katzenpost/blob/main/docs/specs/kaetzchen.md

[KATZMIXE2E]{#KATZMIXE2E .citation-label}

Angel, Y., Danezis, G., Diaz, C., Piotrowska, A., Stainton, D.,
\"Katzenpost Mix Network End-to-end Protocol Specification\",
July 2017,
https://github.com/katzenpost/katzenpost/blob/main/docs/specs/old/end_to_end.md

[KATZMIXNET]{#KATZMIXNET .citation-label}

Angel, Y., Danezis, G., Diaz, C., Piotrowska, A., Stainton, D.,
"Katzenpost Mix Network Specification",
June 2017,
https://github.com/katzenpost/katzenpost/blob/main/docs/specs/mixnet.md

[KATZMIXPKI]{#KATZMIXPKI .citation-label}
Angel, Y., Diaz, C., Piotrowska, A., Stainton, D.,
"Katzenpost Mix Network PKI Specification",
November 2017,
https://github.com/katzenpost/katzenpost/blob/main/docs/specs/pki.md

[KATZMIXWIRE]{#KATZMIXWIRE .citation-label}
Angel, Y.,
"Katzenpost Mix Network Wire Protocol Specification",
June 2017.
https://github.com/katzenpost/katzenpost/blob/main/docs/specs/wire-protocol.md

[LOOPIX]{#LOOPIX .citation-label}
Piotrowska, A., Hayes, J., Elahi, T., Meiser, S., Danezis, G.,
"The Loopix Anonymity System", USENIX,
August, 2017
https://arxiv.org/pdf/1703.00536.pdf

[RFC2119]{#RFC2119 .citation-label}
Bradner, S.,
"Key words for use in RFCs to Indicate Requirement Levels",
BCP 14, RFC 2119, DOI 10.17487/RFC2119,
March 1997,
http://www.rfc-editor.org/info/rfc2119

[ZCASHINTEGRATION]{#ZCASHINTEGRATION .citation-label}
https://z.cash/support/zig.html

[ZCASHPAYMENTAPI]{#ZCASHPAYMENTAPI .citation-label}
https://github.com/zcash/zcash/blob/master/doc/payment-api.md
