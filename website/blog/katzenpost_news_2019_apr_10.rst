.. post:: Apr 10, 2019
   :tags: katzenpost, blog
   :title: Katzenpost Monthly News Update
   :author: David Stainton
   :nocomments:

Apr 10, 2019

Katzenpost Monthly News Update
------------------------------

Greetings,

The Panoramix grant project funded by the European Commission has
officially ended but the Katzenpost free software project lives on.
Masala and I continue to work on Katzenpost for grant money given to
us by Samsung.

We recently learned a few things about mixnet design in a series of
design meetings. The conclusions from our learnings is too much
information and detail for this here post. However I will summarize
some of our conclusions below. Our discussions usually revolved around
mixnet CRDT applications, client reliability, message spool server
design, client decoy traffic and, preventing attacks: statistical
disclosure and active confirmation attacks.

Although far from complete, we added some design considerations to the
following draft specification documents:

https://github.com/katzenpost/katzenpost/blob/master/docs/drafts/client.rst
https://github.com/katzenpost/katzenpost/blob/master/docs/drafts/deaddrop.rst
https://github.com/katzenpost/katzenpost/blob/master/docs/drafts/decoy_traffic.rst

The new Katzenpost mixnet design will work as follows:

* Clients will NOT send each other messages directly to each other's
Provider. A client's Provider and spool ID is kept secret while
clients share remote spool identities and remote spool Providers with
each other instead. This allows a threat model of mutual distrust
between clients. This design can help prevent clients from leaking
more metadata such as geographical location.

* Messages are encrypted as follows: Firstly, the higher layer
communications channel mechanism will use a modern cryptographic
ratchet for forward secrecy and post compromise security
properties. However, this ciphertext will be encapsulated by the Noise
X oneway handshake. The nonce used by Noise X ensures that even if the
client transmits the ratchet ciphertext, the Noise X ciphertext will
always look different. This accomplishes our goal of not leaking
retransmissions to spool Providers.

* Spool servers are now kept outside of the Katzenpost mix server
source repository. That is to say, we make use of a plugin system for
our mix server so that Providers can add arbitrary services to the mix
network. We intend to use an iterative approach to designing and
implementing remote message spools. The basic messaging use case as
described above can be improved in the future by implementing the
message spools as CRDT's. This will allow spools to be replicated and
this eliminates single points of failure in the network. In contrast
the original Loopix design, each client has a single message spool on
their Provider. If this Provider has an outage then that client will
be unable to access their message spool.

* Clients and mixnet plugin services will together optionally make use of a
publish subscribe protocol.

* Clients will send normal and decoy traffic in accordance with the timing
provided by the original Loopix tuning parameters: λP, λL, λD, λM.


Our mission is to enable other communications software projects to use
mix networks to reduce their metadata leakage. To that end we have
been working on mixnet client libraries that can be used by anyone.
Although in the future we are planning to write a generic client
daemon which you can interact with using a Unix domain socket. We hope
that this will be an effective combination for enabling other projects
to use a Katzenpost mix network.

Although we are still in an unstable and rapid development phase
we made some recent improvements to the Katzenpost mix server:

* Made it support running in networked environments with NAT devices.

* Added a new plugin system which is hopefully less annoying to use
than our existing gRPC based plugin system. The new plugin system uses
CBOR over HTTP over Unix domain sockets. Katzenpost mix server plugins
allow you to add arbitrary query/response services to your mix
network. That is, you send a SURB and a query payload to a service and
it can send one reponse using that SURB.

I've provided some "echo" service plugins as examples of how to write plugins
for Katzenpost in our server_plugins repo:

https://github.com/katzenpost/katzenpost/server_plugins

HOWEVER, we have for over a year supported BTC and Zcash cryptocurrency submitions
via the "currency" plugin, here:

https://github.com/katzenpost/katzenpost/tree/master/server_plugins/grpc_plugins/currency

Other areas of improvement include fixing some bugs in the Voting
Authority server and changing our PKI document to include all the
Loopix tuning parameters: λP, λL, λD, λM. Thanks to Masala and Moritz
we made recent progress in implementing a continuous integration
system that runs kimchi based integration tests.

Yes, Katzenpost is a general purpose transport for message oriented
applications. All client applications using the mix network look the
same. My "elite dark mixnet wallet" for Zcash will have a traffic
profile of λP, λL, λD just like mixnet chat client. Just as soon as
we stabilize our client library we will actively seek collaborations
with application developers.


I've made a few screencasts to explain about mix networks and Katzenpost:

* Katzenpost Introduction draft
https://www.youtube.com/watch?v=vDJihqksd6w

* A Brief Introduction to mix networks
https://www.youtube.com/watch?v=1VMUb47QhfE

* Mix Network Topology
https://www.youtube.com/watch?v=bxk4H_X_OsM

* Introduction to Statistical Disclosure Attacks and Defenses for Mix Networks
https://www.youtube.com/watch?v=pHLbe1JKrAQ




Cheers,

David Stainton
