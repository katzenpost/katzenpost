---
title: "PANDA Autoresponder Extension"
description: ""
categories: [""]
tags: [""]
author: ["David Stainton"]
version: 0
draft: true
---

**Abstract**

This document describes the behavior of a PANDA (see [PANDA] and
[PANDASPEC]) server implemented as a Provider side autoresponder
service [KAETZCHEN]. This Panda Kaetzchen service can be used as an
alternative to [KATZKEYSERVER].

## Introduction

PANDA, Phrase Automated Nym Discovery Authentication is a variation
of [EKE2] a PAKE, Password Authenticated Key Exchange, with some
design variations that allows clients to perform the key exchanges
asynchronously. The Panda protocol has three principals, two
clients and one server. The clients have identical behavior and do
all the crypto while the server is very simple and merely
facilitates the exchanges of cryptographic binary blobs.

### 1.1. Terminology

* PAKE: Password Authenticated Key Exchange

* PANDA: Phrase Automated Nym Discovery Authentication: see [PANDA]
    and [PANDASPEC].

* kaetzchen/autoresponder service: A service which runs on a
    Provider and uses a request-response style protocol scheme to
    implement arbitrary services for mix network clients. See
    [KAETZCHEN] for details.

* Provider: A service operated by a third party that Clients
    communicate directly with to communicate with the Mixnet.  It is
    responsible for Client authentication, forwarding outgoing
    messages to the Mixnet, and storing incoming messages for the
    Client. The Provider MUST have the ability to perform
    cryptographic operations on the relayed packets.

* Posting: A structure referenced by a unique identifier (a Tag),
    containing two message slots for storing binary blobs on the
    Panda server's storage subsystem.

* Tag: A 32 byte value used to reference a Posting.

### 1.2 Conventions Used in This Document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [RFC2119].

## 2. System Overview

The server side of the Panda protocol assumes that two Panda
clients have previously selected a Panda server to use. Panda
servers act like a bulletin board system, however a particular
Posting is only visible to clients that present the associated 32
byte Tag identifier.

The two Panda clients use the Panda server to make two binary blob
exchanges. Panda clients uses their binary blobs to facilitate an
authenticated key exchange. The full Panda protocol details are
described in [PANDASPEC].

The Panda server stores a simple data structure called a Posting
which has two message slots and is referenced by a tag. If Alice
manages to contact the Panda server before Bob then Alice's message
will be inserted into Slot 1. Alice's client will then periodically
check the Posting for Bob's message in Slot 2. When Bob finally
contacts the Panda server he inserts his message into Slot 2 and
receives Alice's message from Slot 1.

```
.--------.      .----------.      .-------.      .-------.
| Bob    | ---> | Provider | ---> |  Mix  | ---> |  Mix  | -------.
`--------' <--- `----------'_     `-------'      `-------'         \
                            |\     .-------.      .-------           |
                            '--- |  Mix  | <--- |  Mix  | <---.    |
                                '-------'      `-------'      \   |
                                                                |  V

                                                        .-- Panda Server --.
                                                        |      .---------. |
                                                        |      | Posting | |
                                                        |      |         | |
                                                        |      | Slot 1  | |
                                                        |      | Slot 2  | |
                                                        |      |         | |
                                                        |      `---------' |
                                                        `------------------'
                                                                |  Ʌ
                                .-------.      .-------        /   |
                            .---- |  Mix  | <--- |  Mix  | <----'    |
                        |/_     '-------'      `-------            |
.--------.      .----------.      .-------.      .-------.          /
| Bob    | ---> | Provider | ---> |  Mix  | ---> |  Mix  | --------'
`--------' <--- `----------'      `-------'      `-------'
```

## 3. Panda Server Parameters

The Panda Server is parameterized by the implementation
based on the application and security requirements.

- POSTING_TAG_LENGTH - It is recommended that the Tag length be 32 bytes.
- MAX_SLOT_LENGTH - As specified in [KAETZCHE], the request and response messages
    are limited in size by the max payload size of the Sphinx packets.
- EXPIRATION_DURATION - The duration a Posting can remain on the Panda server
    without being expunged by garbage collection.

### 3.1 Public Panda Parameters

Panda server implementations SHOULD publish their EXPIRATON_DURATION in
their parameters section of their entry in the PKI document as detailed
in [KAETZCHEN].

## 4. Protocol Messages

The PandaRequest is sent to the Panda service with a SURB
that is used to send the PandaResponse back to the client.

### 4.1 PandaRequest message

```
{
    "Version": 0,
    "Tag": "8151d5513e0e4c44e4fee37f07a524ce646141dd10a59718ef223c06dea41b8c",
    "Message": "QPXc2+lEruQXNe3PNpDfM+Uh1cajoSkpS+jioWUdys2WzzBu2wBEzx6qs7TXe+5VrdyMn9dkVrFywwJr"
}
```

Notes:

- The Tag field is hex string encoding a 32 bytes value.
- The Message is a variable length base64 encoded binary blob.

### 4.2 PandaResponse message

```
{
    "Version": 0,
    "StatusCode": "0",
    "Message": "gtjbknqV+fc9FzKlmDB8wVKZhbqWq6+nDV4S/rD/PzRjV5MMeR+cE0swfsBkxlqGlQHb5wSefNee0Wxg"
}
```

Notes: The StatusCode field is used to report errors to the client if any.

Valid status codes are:

```
enum {
    status_received1(0),                  /* Message1 was received. */
    status_received2(1),                  /* Message2 was received. */
    status_syntax_error(2),               /* The request was malformed. */
    status_tag_collision_error(3),        /* The request tag collision error. */
    status_tag_request_recorded_error(4), /* The request message was already recorded. */
    status_storage_error(5),              /* Storage subsystem failure. */
} StatusCodes;
```

The Message field is variable length and base64 encoded, it
contains the retrieved message from a previously queued Posting.
This field MAY be empty such as in the case where the Panda
server does not find the specified tag in it's storage subsystem.

## 5. Panda Server Storage

The Panda servers stores Postings of the following format:

```
struct {
    uint64_t unix_time;
    opaque slot1[];
    opaque slot2[];
} Posting;
```

Notes:

- The unix_time field specifies the time when the Posting was persisted to disk.
- slot1 and slot2 are the two message slots.

### 5.1 Garbage Collection

The Panda server MUST periodically garbage collect expired Postings.

## 6. Anonymity Considerations

Mix network based transports are a good choice for implementing
the Panda protocol because they are message oriented and hide the
identity/location of clients from the Panda server.

## 7. Security Considerations

After the two binary blob exchanges are performed, the Panda
server does NOT expunge the two Postings because the Kaetzchen
protocol is lossy. Therefore the Panda server must not assume the
client will receive the PandaResponse message. The queued
ciphertext on the Panda server represents vulnerability to a
compulsion attack. That is, an adversary might break the
confidentiality guarantee using a key compromise.

Panda is not a post quantum cryptographic protocol and therefore
a sufficiently motivated adversary may be able to violate the
decisional Diffie-Hellman assumption using a quantum computer
after capturing queued ciphertext blobs.

## 8. Future Work

Future versions may decide to use a stricter eviction policy
in exchange for reduced ciphertext availability.

It might be possible to design a decentralised variation of
the Panda protocol to remove the dependency on a single server
for ciphertext availability.

## Appendix A. References

### Appendix A.1 Normative References

[RFC2119]
Bradner, S.,
"Key words for use in RFCs to Indicate Requirement Levels",
BCP 14, RFC 2119, DOI 10.17487/RFC2119,
March 1997,
http://www.rfc-editor.org/info/rfc2119

[KAETZCHEN]
Angel, Y., Kaneko, K., Stainton, D.,
"Katzenpost Provider-side Autoresponder",
January 2018,
https://github.com/katzenpost/katzenpost/blob/main/docs/specs/kaetzchen.md

### Appendix A.2 Informative References

[PANDA]
Appelbaum, J.,
"Going Dark: Phrase Automated Nym Discovery Authentication",
https://github.com/agl/pond/tree/master/papers/panda

[PANDASPEC]

[SPAKE2]
Abdalla, M., Pointcheval, D.,
"Simple Password-Based Encrypted Key Exchange Protocols",
Topics in cryptology–CT-RSA 2005,
http://www.di.ens.fr/users/mabdalla/papers/AbPo05a-letter.pdf

[EKE2]
Bellare, M., Pointcheval, D., Rogaway, P.,
"Authenticated Key Exchange Secure Against Dictionary Attacks",
EUROCRYPT,
April 2000,
https://eprint.iacr.org/2000/014.pdf

[KATZKEYSERVER]
Angel, Y., Diaz, C., Pollan, R., kwadronaut, mo, Kaneko, K., Stainton, D.,
"Katzenpost Key Discovery Extension", February 2018,
https://github.com/katzenpost/katzenpost/blob/main/docs/drafts/keyserver.md
