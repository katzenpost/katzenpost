.. post:: Nov 22, 2018
   :tags: katzenpost, blog
   :title: Katzenpost Monthly News Update
   :author: David Stainton
   :nocomments:

Nov 22, 2018

katzenpost news
---------------

Greetings!

This is our second edition of katzenpost news.
There's been a lot of progress since the last report I posted many months ago.


Firstly I'd like to mention our future development plans:

* mix and directory authority key agility
* generative testing for the voting Directory Authority system
* generative testing for all of the things where appropriate
* load and performance testing the mix server
* design and development of an application agnostic mixnet client message oriented protocol library
* design and development of one or more applications that use our new mixnet protocol client library
* potentially assist in integration with other software projects that want to use a mixnet transport protocol


Our recent accomplishments include:

* Eradication of our usage of JOSE/JWS and usage of the golang Jose library.
  We no longer use JOSE/JWS for signing mix descriptors and directory authority documents.
  Instead we use the "cert" library I wrote which gives us certificate format agility AND
  cryptographic algorithmic agility.

specification:
https://github.com/katzenpost/katzenpost/blob/master/docs/specs/certificate.rst

golang implementation:
https://github.com/katzenpost/katzenpost/tree/master/core/crypto/cert


* Our mix server now has a language agnostic plugin system for adding
  mixnet services. We have a modular API that allows you to write new
  services in golang and staticly compile them into the binary, however
  this new plugin system allows you to add services using external
  programs as plugins. These external plugins use gRPC over Unix domain
  socket to talk to the mix server (Provider). Using these plugins we
  can make new mixnet protocols that are either one way or strict call
  and response protocols that use SURBs to send the replies.

Here's the mix server documentation for this new feature:
https://github.com/katzenpost/katzenpost/blob/master/docs/handbook/mix_server.rst#external-kaetzchen-plugin-configuration

Here's the Kaetzchen specification document which explains a bit how this
plugin system works although it doesn't discuss implementation details:
https://github.com/katzenpost/katzenpost/blob/master/docs/specs/kaetzchen.rst

This repository contains an "echo service" written in Rust, Golang and Python.
Also it contains a plugin to perform crypto currency submissions, the idea being
that mixnets can be used to transport a transaction blob to a Provider service
which then submits the transaction to the database, the blockchain or whatever:

https://github.com/katzenpost/katzenpost/server_plugins


* we now have a set of incomplete Katzenpost Handbook documents:

https://github.com/katzenpost/katzenpost/blob/master/docs/handbook/index.rst

Mailproxy Client Daemon
https://github.com/katzenpost/katzenpost/blob/master/docs/handbook/mailproxy.rst

Katzenpost Mix Server Infrastructure
https://github.com/katzenpost/katzenpost/blob/master/docs/handbook/mix_server.rst

Katzenpost Mix Network Public Key Infrastructure
https://github.com/katzenpost/katzenpost/blob/master/docs/handbook/nonvoting_pki.rst

Torification of Katzenpost
https://github.com/katzenpost/katzenpost/blob/master/docs/handbook/tor.rst

Katzenpost Voting Directory Authority
https://github.com/katzenpost/katzenpost/blob/master/docs/handbook/voting_pki.rst


* we now have a HACKING guide for new Katzenpost developers:

https://github.com/katzenpost/katzenpost/blob/master/docs/HACKING/index.rst


* we now have a release process and some binary releases:

https://github.com/katzenpost/katzenpost/blob/master/docs/release_checklist.rst
https://github.com/katzenpost/katzenpost/blob/master/docs/releases.rst
https://github.com/katzenpost/daemons/releases


* We have released the voting Directory Authority (mixnet PKI)
  implementation since it is known to work properly as far as we were
  able to test thus far. This was more work and more difficult than we
  originally anticipated for both design and programming the
  implementation.

The design of this PKI was not fully supported by the Panoramix grant project
because our academic collaborators were not under official obligation to work
on this given that our three month period of design work officially ended.
Thus, we were fortunate to receive their advice anyway.

Our specification document is rather still rather incomplete unfortunately:

https://github.com/katzenpost/katzenpost/blob/master/docs/specs/pki.rst

Masala has done most of the development work and together we fixed
some bugs in the implementation. The design of our PKI is a synthesis
of design ideas that come from some brilliant minds and we'd like to
thank Yawning Angel, Claudia Diaz, Ania Piotrowska and Nick Mathewson.

Our PKI uses a Shared Random Value to seed the randomization of our topology.
We'd like to thank George Kandianakis for answering our questions about Tor's
hash based commit and reveal shared random value protocol.

What does randomizing our topology mean? Loopix and Katzenpost use the stratified
topology which means that the client's path selection must select a mix from
each layer. This topology is enforced by our mix link layer protocol.
The PKI generates and publishes a network consensus document\ and this specifies
which mixes belong in which topology layer.

When one or more mix network layers change such that they only contain
mixes operated by a single operators or contain only one mix that is what we
mean by imbalanced. "Too few security domains" gives too much control over
path selection to one or more mix operators.

The voting Directory Authority servers detect these mix outages by the
absense of a newly uploaded mix descriptors for the voting
round. Upon detecting this threshold event the shared random value is
used to seed topology randomization. Claudia and Ania rightly pointed
out that we MUST try to avoid rerandomization, it is detrimental to
the anonymity properties of the mix network because it splits each
mix's anonymity set into two. That is, incoming messages for each mix
are either from layer X or from layer Y, this topology distinction in
message source means that those two categories of messages will not be
mixed together and this is what is meant by splitting the anonymity
set into two.


* Masala and I fixed a plethora of race conditions in client and server code
for both the Directory authority and mix servers.


* I added a prototype mixnet client and server for supporting Adam Langely's PANDA protocol:

https://github.com/katzenpost/katzenpost/panda

PANDA was used in Pond, and Pond has sadly been abandoned by it's creator.
I would like there to be many useful mixnet clients, including a kind of
"Pond replacement" that can perform key exchanges using PANDA.

During the last section of my mixnet talk at Bornhack 2018 I demonstrated
the mixnet PANDA client and server working:

https://www.youtube.com/watch?v=DhBWKWQztdA



Sincerely,
David Stainton
