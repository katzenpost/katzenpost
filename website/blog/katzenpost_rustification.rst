.. post:: Jan 13, 2019
   :tags: katzenpost, blog
   :title: Katzenpost Rustification
   :author: David Stainton
   :nocomments:

Jan 13, 2019

Katzenpost Rustification
------------------------

Hi,

I wrote some notes about making mixnet components in Rust that are binary
compatible with existing Katzenpost components.
( https://github.com/katzenpost/katzenpost/blob/master/docs/drafts/priority_tasks.rst#rustification )

Rustification
=============

The goal should be binary compatibility with the golang implementation
of Katzenpost such that the existing golang components can
interoperate with the new Rust components. Perhaps the biggest advantage
of using Rust would be for writing mixnet clients as opposed to mix servers.
A Rust mixnet client could easily present a FFI that could be used by
user interfaces written in Java for Android and Swift for iOS.

I wrote several relavant rust crates:

* https://crates.io/crates/aez
* https://crates.io/crates/ecdh_wrapper
* https://crates.io/crates/mix_link
* https://crates.io/crates/rust-lioness
* https://crates.io/crates/epoch
* https://crates.io/crates/sphinx_replay_cache
* https://crates.io/crates/sphinxcrypto


Sphinx binary compatibility
---------------------------

* https://crates.io/crates/sphinxcrypto

The rust Sphinx uses the exact same cryptographic primitives
as the golang implementation. Therefore it should be fairly
easy to make them binary compatible. They should share test vectors.


Mix link layer binary compatibility
-----------------------------------

* https://crates.io/crates/mix_link

Currently this mix link layer crate uses ``Noise_XX_25519_ChaChaPoly_BLAKE2b``
however if the Katzenpost link layer were to upgrade to
Kyber then the task of making this crate binary compatibility
would be greatly simplified.

Here's an implementation of Kyber:

* https://crates.io/crates/kyber

This ``mix_link`` crate uses the snow Noise protocol library implementation:

* https://crates.io/crates/snow

However we SHOULD patch snow with Kyber PQ KEM hybrid forward secrecy.
Here's the snow github ticket for this task:

* https://github.com/mcginty/snow/issues/39


Mix server
----------

Current work in progress rust mix server:

* https://github.com/david415/mix_server

Development progress has halted due to not being able to interoperate
with the existing Katzenpost Directory Authority system.
