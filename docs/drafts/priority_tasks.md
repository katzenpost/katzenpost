---
title: "Priority Development tasks (which do not include design work)"
description: ""
categories: [""]
tags: [""]
draft: true
---

Here is where we outline which developments tasks are urgent and less so.

## Unit tests

The mix server and Directory Authority server should have unit tests
that can be used with a continuous integration system such as Travis.
This should hopefully shed light on some Directory Authority server bugs
and help us fix them as well as prevent regressions.

# Priority Design tasks

## Upgrade Link Layer Protocol

Upgrade mixnet link layer to use the Kyber PQ KEM instead of New Hope
Simple because Dr. Peter Schwabe says it\'s a good idea. It also greatly
simplifies rustification. Before this development task begins the
specification document should reflect the necessary changes:

- https://github.com/katzenpost/katzenpost/blob/master/docs/specs/wire-protocol.md

## Key Agility

Currently Katzenpost mix servers and Directory Authority servers do not
have key agility. That is to say, there is no way for these servers to
change their static identity keys. The two primary reasons for key
agility are recovery from a known key compromise and as a prerequisite
for usage with a hardware security module.

Early unfinished key agility draft specification document:

- https://github.com/katzenpost/katzenpost/blob/master/docs/drafts/key_agility.md

## Client Library

Early unfinished draft specification document:

- https://github.com/katzenpost/katzenpost/blob/master/docs/drafts/client.md

After this draft specification document is completed additional
composable libraries should be designed which have more sophisticated
encryption as provided by the Signal Double Ratchet or OTRv4.

## Rustification

The goal should be binary compatibility with the golang implementation
of Katzenpost such that the existing golang components can interoperate
with the new Rust components. Perhaps the biggest advantage of using
Rust would be for writing mixnet clients as opposed to mix servers. A
Rust mixnet client could easily present a FFI that could be used by user
interfaces written in Java for Android and Swift for iOS.

I wrote several relavant rust crates:

- https://crates.io/crates/aez
- https://crates.io/crates/ecdh_wrapper
- https://crates.io/crates/mix_link
- https://crates.io/crates/rust-lioness
- https://crates.io/crates/epoch
- https://crates.io/crates/sphinx_replay_cache
- https://crates.io/crates/sphinxcrypto

## Sphinx binary compatibility

- https://crates.io/crates/sphinxcrypto

The rust Sphinx uses the exact same cryptographic primitives as the
golang implementation. Therefore it should be fairly easy to make them
binary compatible. They should share test vectors.

## Mix link layer binary compatibility

- https://crates.io/crates/mix_link

Currently this mix link layer crate uses
`Noise_XX_25519_ChaChaPoly_BLAKE2b` however if the Katzenpost link layer
were to upgrade to Kyber then the task of making this crate binary
compatibility would be greatly simplified.

Here's an implementation of Kyber:

- https://crates.io/crates/kyber

This `mix_link` crate uses the snow Noise protocol library
implementation:

- https://crates.io/crates/snow

However we SHOULD patch snow with Kyber PQ KEM hybrid forward secrecy.
Here's the snow github ticket for this task:

- https://github.com/mcginty/snow/issues/39

## Mix server

Current work in progress rust mix server:

- https://github.com/david415/mix_server

Development progress has halted due to not being able to interoperate
with the existing Katzenpost Directory Authority system.
