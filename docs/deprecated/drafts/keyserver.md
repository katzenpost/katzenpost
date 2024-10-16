---
title: "Key Discovery Extension"
description: ""
categories: [""]
tags: [""]
author: ["Yawning Angel", "Claudia Diaz", "Kali Kaneko", "kwadronaut", "Ruben Pollan", "mo", "David Stainton"]
version: 0
draft: true
---

**Abstract**

This document describes a mechanism for user identity key discovery that
is to be used with the Katzenpost end to end protocol as described in
[KATZMIXE2E](#KATZMIXE2E){.citation} for end to end client
encryption of messages.

# 1. Introduction

This key discovery service is implemented as a Provider-side
autoresponder [KAETZCHEN](#KAETZCHEN){.citation}. Clients send a
request message and wait to receive a response message. Keys exchanged
with this service are not end to end authenticated. Authentication of
keys must be done out of band.

## 1.1 Conventions Used in This Document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
[RFC2119](#RFC2119){.citation}.

## 1.2 Terminology

- `Provider` - A service operated by a third party that Clients
  communicate directly with to communicate with the Mixnet. It is
  responsible for Client authentication, forwarding outgoing messages
  to the Mixnet, and storing incoming messages for the Client. The
  Provider MUST have the ability to perform cryptographic operations
  on the relayed messages.
- `Kaetzchen` - A Provider-side autoresponder service as defined in
  [KAETZCHEN](#KAETZCHEN){.citation}.

# 2. Overview

A Client, Alice, may discover Bob\'s key by sending a KeyserverRequest
to Bob's Provider and waiting for a KeyserverResponse containing Bob's
key.

```
.--------.        .----------.        .-------.        .-------.
| Alice  |  --->  | Provider |  --->  |  Mix  |  --->  |  Mix  |  ----.
`--------'        `----------'        `-------'        `-------'       `\
                                                                            |
.-----.           .----------.                                          /
| Bob |  ------>  | Provider |  <--------------------------------------'
`-----'  <------  `----------'
```

## 3. Protocol Messages

The KeyserverRequest is sent to the key discovery service with a SURB
that is used to send the KeyserverResponse back to the client.

### 3.1 KeyserverRequest Message

```
{
    "Version": 0,
    "User": "Alice"
}
```

Notes:

- The User field specifies which identity key to retrieve.

### 3.2 KeyserverResponse Message

```
{
    "Version": 0,
    "StatusCode": 0,
    "User": "Alice",
    "PublicKey": "33BB41546AF0CC576AFA631D28B6A6CDFE4DF36CAF9038B942E3A32AC433667D"
}
```

Notes:

- The StatusCode field is used to report errors to the client if any. Valid status codes are:

```
enum {
    status_ok(0),            /* No error condition. */
    status_syntax_error(1),  /* The request was malformed. */
    status_no_identity(2),   /* The specified identity was not found. */
} StatusCodes;
```

- The User field is used to specify the identity.
- The PublicKey field contains the hex encoded X25519 public identity
  key for the given User.

## 4. Client-side Behavior

Clients maintain a local database of contact keys which can be in one of
three states:

- RECEIVED-ONLY
- UNVERIFIED
- VERIFIED

On receiving a message from an unknown identity key included with the
signed message, the key MUST be marked as RECEIVED-ONLY.

In the case of a sender for whom the user only has a key flagged as
RECEIVED-ONLY, and before the moment of establishing communication with
such sender, the users\' client SHOULD trigger a key lookup against the
Kaetzchen agent specified by the sender's provider, if any.

Otherwise, an identity key verified by means of an out-of-band
mechanism, or in its absence a key marked as RECEIVED-ONLY will be used
for end to end encryption with this identity. If such a key lookup
results in a mismatch then the Client user interface MUST present a
warning to the user.

A given identity received via the key discovery defined in this
specification MUST be marked as unverified until the Client marks it as
verified by means of an out-of-band mechanism. Defining the means of
verification is out of scope of this document.

Clients SHOULD periodically send requests to its own key, and the UI
MUST display some kind of warning in case of a mismatch or failure.
Clients MAY also send warnings to already verified recipients about this
failure in the lookup.

## 5. Anonymity Considerations

*TODO: this section doesn't make sense and needs cleanup.*

This mechanism allows for a malicious provider to learn about the online
activity of a given user by creating dummy identities that produce a key
lookup that the malicious provider can observe.

Countermeasure would include applying a random delay on the send queue
for the first hop ("offline send helper"), and leaving the account in
an "unusable" state. This effectively limits the information leakage
after the first hop. This countermeasure is also helpful to paliate the
time window in which ... DISCUSS

In order to avoid user enumeration attacks, every request to the
Kaetzchen MUST include the lookup of one and only one key.

The sender provider SHOULD/MAY also implement traffic rate
limitations to the amount of request per unit of time that a given
client can emit. This is a generic defense against spam that is also
effective against user enumeration 

*TODO: CROSS-REF to some other proper spec*

(How can a provider tell if a given message is a key lookup? The side
servicing a request can, but they don't know who's sending the
request. The side that\'s sending the request can't tell :P) kali:
meskio's proposal considers that this probably doesn't belong here,
but the rationale is to defend against aspam

It's a good idea, but it falls more under, "providers should limit how
much traffic any given client can dump into the mixnet at once". yep.
what do you think is the right spec to drop this consideration in?

Not sure. There's a comment in the server code that says "Add rate
limiting here.", past that I didn't give this much thought.

*TODO: If clients should be rate-limited in how fast they can send
packets, this is probably the natural place to do so.*

Right now everything assumes clients are moderately well behaved.

## 6. Security Considerations

- We rely on visual confirmation of the user ID on both ends, so homoglyphs in user IDs MUST be prohibited.

## 7. Future Work

- Key rotation implies key refreshes. How is this to be made in a way that doesn't leak info?

## Appendix A. References

### Appendix A.1 Normative References

### Appendix A.2 Informative References


[KAETZCHEN]{#KAETZCHEN .citation-label}

Angel, Y., Kaneko, K., Stainton, D.,
"Katzenpost Provider-side Autoresponder",
January 2018,
https://github.com/katzenpost/katzenpost/blob/main/docs/specs/kaetzchen.md

[KATZMIXE2E]{#KATZMIXE2E .citation-label}

Angel, Y., Danezis, G., Diaz, C., Piotrowska, A., Stainton, D.,
"Katzenpost Mix Network End-to-end Protocol Specification",
July 2017,
https://github.com/katzenpost/katzenpost/blob/main/docs/specs/old/end_to_end.md

[RFC2119]{#RFC2119 .citation-label}

Bradner, S.,
"Key words for use in RFCs to Indicate Requirement Levels",
BCP 14, RFC 2119, DOI 10.17487/RFC2119,
March 1997,
http://www.rfc-editor.org/info/rfc2119
