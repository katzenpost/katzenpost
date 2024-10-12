---
title: "DSpool: Durable ephemeral soft-queues without single points of failure"
description: ""
categories: [""]
tags: [""]
author: ["Leif Ryge", "David Stainton"]
version: 0
draft: true
---

**Abstract**

This is intended to be used as a store-and-forward medium for
publish-subscribe types of applications, such as mailboxes for chat or
email and email-like systems, and as a general-purpose inter-process
communication mechanism for any message-oriented application where a
strict ordering of messages is not required.

## 1. Introduction

We present a system providing durable storage of semi-ordered data for
both long-term and ephemeral applications, without relying on single
points of failure, using a CRDT construction with cryptographic
capabilities inspired by [TAHOELAFS](#TAHOELAFS){.citation} to
define who can read, write, replicate, and delete the data, as well as
who can grant and revoke the other capabilities.

In particular:

- writers should be able to tell how many replicas have received their write
- if a replica is compromised/malicious, it should only be able to DoS
  subsequent operations that it is asked to perform (which should be
  easily detectable) and able to perform a limited amount of traffic
  analysis.

## 1.1 Terminology

- `CRDT` - Conflict-free replicated data type is a data structure
  which can be replicated across multiple computers in a network,
  where the replicas can be updated independently and concurrently
  without coordination between the replicas, and where it is always
  mathematically possible to resolve inconsistencies which might
  result.
- `node` - A node is an operator which provides services, and has a
  stable address where it can receive requests. In addition to the
  various keypairs it has for performing its services, it has a single
  long-term identity keypair.
- `operator` - An operator is an agent that controls one or more
  keypairs and is able to initiate requests.
- `Requests` - Requests are sent to nodes by initiators (operators).
  Requests may include a response handle, to which one or more
  responses can be sent to the initiator. Initiators do not need a
  long-term identity; they can potentially be anonymous.
- `PK` - The public part of a keypair.
- `SK` - The secret part of a keypair.
- `SDS` - Signed Discrete Spool. Described below in section 4.
- `AOSDS` - Append-only Signed Discrete Spool is described in section
  4.1.
- `AOROSC` - Add-Once-Remove-Once Set Collection is described in
  section 5.
- `PSDS` - Permissioned Signed Discrete Spool is described in Section
  6.
- `EPSDS` - Encrypted Permissioned Signed Discrete Spool is described
  in section 7.
- `DAS` - Durable Authenticated Spool is described in section 8.
- `pool` - Note: pools aren\'t used in the spec below yet, you can
  ignore them for now. A pool is a content-addressable unordered set.
  That is, a key-value store where the key is the hash of the value.

### 1.2 Conventions Used in This Document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
[RFC2119](#RFC2119){.citation}.

## 2. System Overview

*TODO Write me.*

### 2.1 Ingredients

This specification does not (yet) define which primitives should be
used. These are the types of primitives required by what has been
specified so far:

- A serialization format. (So far, we only need to be able to
  serialize tuples of bytestrings, but this will probably change.)
- A signature scheme, optionally supporting ring signatures (for
  multiple writers where the replicas cannot tell which writer is
  writing)
- A hash function.
- An asymmetric encryption scheme.

We are also not defining how to find out about the nodes which provide
services; at this layer we assume that there is some external mechanism
by which users learn about nodes\' keys and addresses.

## 3. Discrete spool

A discrete spool is an ordered list of items. It is an object
implementing these methods:

- `append(message) -> index` Writes a message to the spool.
- `message` is a bytestring
- `index` is the index of the item that was just written (which is the length of the spool minus 1)
- `read(index, limit=1) -> series of messages` Returns the item at index, and some number of items after it.
- `index` is a position in the spool.
- `limit` is a maximum number of messages to return, or 0 for all messages
- `forget(index)` forgets everything older than index.
- `index` is a position in the spool.

The discrete spool interface is not intended to be provided to more
than one entity, it is a low-level local interface upon which the
following interfaces may be implemented.

## 4. Signed discrete spool

- Also known as SDS.

A signed discrete spool is like a discrete spool, but is initialized
with a PK called the \"spool key\". It can be implemented on top of a
discrete spool. A SDS has these methods:

- `append(message, spool_signature) -> index`  Writes a message to the spool.

Note that the message written to the underlying discrete spool is actually (message, spool_signature).

- message is a bytestring
- index is the index of the item that was just written (which is the length of the spool minus 1)
- spool_signature is a signature from the spool SK over (message, spool_signature-of-previous-message)
- `read(index, limit=1) -> series of (message, spool_signature)`

Returns the item at index, and some number of items after it.

- index is a position in the spool.
- limit is a maximum number of messages to return, or 0 for all messages
- `forget(index)` Forgets everything older than index.
- `index` is a position in the spool.

Note that writing to an SDS requires knowing its current state. In
general, it is expected that only a single operator would write via this
interface, and that the single operator would have exclusive access to
the interface for it (and the spool key that is required to write to
it).

If multiple uncoordinated writers are desired (which would require that
each have a copy of the same single secret key) they will need to be
prepared have their writes fail when other writes have occurred since
their previous read.

Possibly a strict mode should exist wherein a second valid
spool_signature over an already-used previous state is considered
evidence of key compromise, and triggers an exceptional state.

The read interface MAY be made available to other parties, which might
make sense for some applicatons. The forget method obviously MUST NOT be
made directly available to others, as it is unauthenticated at this
layer.

Note that the SDS is roughly equivalent to Secure Scuttlebutt, but with
a forget method.

### 4.1 Append-only Signed Discrete Spool

- Also known as AOSDS.

An append-only SDS is an SDS without the forget method.

## 5. Add-Once-Remove-Once Set Collection

- Also known as AOROSC.

An add-once-remove-once set collection is an AOSDS which defines
membership in various sets. It can be thought of as logically equivalent
to a number of `2P-Set` (two-phase set) CRDTs
[WIKICRDT](#WIKICRDT){.citation}.

There are two types of messages which can be written to this spool:

```
add(setname, item)
remove(setname, item)
```

Items and set names are bytestrings.

Attempting to add an item that has already been removed yields an error;
items can be preemptively removed, however.

In addition to the standard AOSDS interface, it has another method:

```
get(setname) -\> set of items
```

This returns the set of items that have been added, minus the set that
have been removed.

Instead of using one AOSDS, a AOROSC could potentially be implemented
using an AOROSC for the tombstones (`remove` messages) and a normal
truncatable SDS for the add messages, but currently it seems like this
optimiziation isn't worth the compexity that it would add.

## 6. Permissioned Signed Discrete Spool

- Also known as PSDS.

A permissioned signed discrete spool consists of an SDS called the data
spool, and an AOROSC called the meta spool. The meta spool describes
membership in sets which define various roles, as well as a special set
called "truncatable" which initially contains one item (the string
"yes").

### 6.1 Roles

- Meta Writer (PKs)
- Meta Reader (PKs)
- Data Writer (PKs)
- Data Reader (PKs)
- Canonical Data Reader (PKs)

*FIXME: define K-of-N schemes here? something with schnorr? later...*

The operator of a PSDS reads from and writes to the data and meta spools
through the SDS and AOROSC interfaces, and provides other operators
permissioned access to them via this interface:

```
{data,meta}_append(message, write_signature) -> receipt
```

Writes a message. Note that the message written to the underlying SDS
is actually (message, write_signature), which means that the messages
in the underlying Discrete Spool are ((message, write_signature),
spool_signature)

- message is a bytestring
- write_signature is a signature over the message from a valid writer key: (or a ring signature from one, using all others' PKs)
- receipt is a a 3-tuple of `(spool_signature, index, spool_signature-of-previous-message)`
- index is a position in the spool
- `{data,meta}_read(index, read_signature, limit=1)` -> series of
  (message, index, write_signature, spool_signature) Returns the item
  at index, and all items after it.
- index is a position in the spool.
- read_signature is a signature (or ring signature) from a valid
  reader key over (index, spool_key)

*Note: the reader signs the spool_key here so that an operator that gets removed can't reuse its signtures to read from other replicas later.*

- limit is a maximum number of messages to return
- write_signature is the message writer's signature
- spool_signature is the operator's signature on the underlying SDS
- forget(tombstone, signature)

Forgets everything in the data spool older than then tombstone
specifies.

- tombstone is a 2-tuple of (replica, prev_spool_signature) refering
  to a previous message (like the index in the read operation)
- signature is a signature over the tombstone, from a canonical reader

*FIXME: here we have a layering violation; the PSDS needs to know about replicas :(*
*Note the differences from the SDS interface:*

- Readers need to authenticate themselves.

*FIXME: should they really? should knowing the spool's identity be
enough to read from it? think POLA; are we relying on operators to
do more than we need them to (or can verify they are doing
correctly) by asking them to provide access control for reads?*

- Writers do not need to know the current state of the spool. (They can't be expected to, because they might not be readers.)
- writers receive a receipt which is a cryptographic claim that the
  PSDS operator wrote the message. the receipt contains the previous
  spool_signature, as well, so that the writer can verify this signature.
- Readers don\'t refer to an absolute index, but rather a relative
  one. The \"index\" in the read operation is NOT the write_signature,
  but rather the spool_signature AND the name of the replica that made
  it.

*FIXME: should that exist at this layer? single-replica PSDS seems
useful, but how to make it fit under the DAS without layering
violations is not so clear still.*

- Truncating the spool requires a signature from a canonical reader. (It is expected that there is typically only one canonical reader.)

When a PSDS is created, an initial writer PK for the meta spool must be
provided. That SK can then be used to write messages to the meta spool
adding reader and writer PKs for the data and/or meta spools.

## 7. Encrypted Permissioned Signed Discrete Spool

- Also known as EPSDS.

From the perspective of the spool operator, an EPSDS behaves just like a
PSDS. The only difference is that there is an additional set in the meta
spool called Data Encryption containing one or more encryption PKs. When
these keys are present, users writing to the spool encrypt their
messages to all of the encryption keys before writing them (using a
scheme left undefined here for now). Readers will then of course need
one of the encryption SKs to decrypt the messages they receive from the
spool operator.

Note that a malicious spool operator cannot simply insert its own
encryption key and cause writers to write to it, because the metaspool
is signed by a Meta Writer key which the reader already knew.

## 8. Durable Authenticated Spool

- Also known as DAS.

A DAS is a semi-ordered spool that is replicated across PSDSes operated
by a number of different nodes. Reads and writes can be performed by
sending requests to any node using cryptographic capabilities containing
keys stored in the PSDSes\' meta spools.

The methods available are the same as the PSDS, except for that instead
of `{data,meta}_append` methods there are `{data,meta}_add`
methods with this signature:

- `{data,meta}_add(message, write_signature) -> series of receipts` from replicas Writes a message. Note that the message written to the underlying SDS is actually `(message, write_signature)`.
-  message is a bytestring
-  write_signature is a signature over the message from a valid writer key (or a ring signature from one, using all others' PKs)
-  `{data,meta}_read(index, read_signature, limit=1)` -> series of `(message, index, write_signature, spool_signature)`

Returns the item at index, and all items after it.

- index is NOT a position in the spool here, because there is no
  longer a fixed ordering of messages at this layer. Instead, index
  is a 2-tuple of `(spool_key PK, spool_signature)`.
- read_signature is a signature (or ring signature) from a valid
  reader key over `(index, spool_key)`
- spool_key is the spool_key of the replica that the reader is
  performing the read from
- note: the reader signs the spool_key here so that an operator
  that gets removed can't reuse its signtures to read from other
  replicas later.
- limit is a maximum number of messages to return
- write_signature is the message writer's signature
- spool_signature is the operator's signature on the underlying SDS

### 8.1 Creation

1. The creator generates a keypair for this DAS called the Root Key.
2. It selects some nodes to act as replicas, and asks each to create a
   new PSDS. The replica nodes are the operators of their respective
   PSDSes; they hold the spool keys. The Root Key is placed in the
   writer role for the meta spools of each.
3. The DAS creator writes replica descriptors for each replica into a
   new "replica" set in each PSDS's meta spool. Each replica
   descriptor contains the replica's PSDS's PK, and one or more
   addresses where that replica can be reached. XXX avoid using the
   term "that replica".
4. Each replica subscribes to each other replica, using the PSDS
   `{data,meta}_read methods`. It will subsequently receive any writes
   to that replica. XXX Not a complete sentence. What the does "that replica" refer to?
5. The DAS creator adds Reader and Writer keys to any replica. Those
   writes are subsequently replicated to the others.

### 8.2 Operation

- Writers can write to any replica. When the other replicas receive
  the messages via their subscriptions to the replica that was written
  to, they validate the signature to ensure it came from a key that
  they currently consider a valid writer, and add it to their own data
  spool.
- When a canonical reader calls the forget method, the replica they
  called it on writes their signed tombstone message into the data
  spool so that other replicas will know that they can forget it.
- When a replica receives a read request with an spool_signature from
  another replica, and that spool_signature is not in the set of
  spool_signatures from that replica which this replica has seen
  before, it returns all messages which are not in the local copy of
  the other replica's spool. XXX avoid using the term "that
  replica". this makes no sense. please stop using the singular term
  replica. it's too generic. try labeling them for clarity and
  writing proper english paragraphs with multiple sentences.

## X. Anonymity Considerations

XXX Write me.

## X. Security Considerations

XXX Write me.

## Appendix A. References

## Appendix A.1 Normative References

XXX Write more references.

### Appendix A.2 Informative References

XXX Write more references. (srsly, wikipedia?)

## Appendix B. Citing This Document

### Appendix B.1 Bibtex Entry

Note that the following bibtex entry is in the IEEEtran bibtex style as
described in a document called "How to Use the IEEEtran BIBTEX Style".

```
@online{Dspool,
title = {DSpool: Durable ephemeral soft-queues without single points of failure},
author = {Leif Ryge and David Stainton},
url = {XXX},
year = {2019}
}
```

[RFC2119]{#RFC2119 .citation-label}

Bradner, S.,
"Key words for use in RFCs to Indicate Requirement Levels",
BCP 14, RFC 2119, DOI 10.17487/RFC2119,
March 1997,
http://www.rfc-editor.org/info/rfc2119

[TAHOELAFS]{#TAHOELAFS .citation-label}

Warner, B., Wilcox-O'Hearn, Z., 2008,
"Tahoe -- The Least-Authority Filesystem"
https://gnunet.org/sites/default/files/lafs.pdf>

[WIKICRDT]{#WIKICRDT .citation-label}

proceedings of wikipedia dot org,
"Conflict-free replicated data type",
https://en.wikipedia.org/wiki/Conflict-free_replicated_data_type#2P-Set_(Two-Phase_Set)
