.. post:: Feb 27, 2018
   :tags: katzenpost, blog
   :title: Katzenpost Monthly News Update
   :author: David Stainton
   :nocomments:


Feb 27, 2018

katzenpost monthly news
-----------------------

Greetings!

This is our first edition of katzenpost monthly news. I'll be
summarizing recent events from our first hackfest in Athens in early
December 2017 to the present.


What we did in Athens:

   * setup a test mix network
   * remote collaboration with Yawning Angel to fix bugs
     and add features to the server side
   * wrote some basic installation documentation
   * Moritz created and deployed the katzenpost website
     with glossary and FAQ https://katzenpost.mixnetworks.org/
   * explored technical issues related to python and java language
     bindings to golang libraries
   * discussed at length the possibilies for various kinds of mixnet
     clients
   * Vincent wrote a prototype android instant messenger client
   * met with the GrNet people and told them how to install a
     katzenpost mix network and answered their questions
   * meskio and kaliy added an external user db interface for Provider authentication
   * meskio wrote prototype python clients for testing purposes
   * we had many group discussion about mix network design
   * special guest visitor: George Kadianakis from Tor Project

Since that time we have been working on our PKI specification. Nick
Mathewson sent us a six page review of our spec and Yawning sent a two
page reply; both of these e-mails contain lots of design details and
have been useful in our editing of the spec thus far:

https://github.com/katzenpost/katzenpost/blob/master/docs/specs/pki.txt

Additionally since the Athens hackfest I, masala and Yawning have made
changes so that interaction with the nonvoting PKI to NOT use HTTP but
instead uses our Noise based wire protocol (which incidentally uses a
Post Quantum hybrid key exchange). The PKI spec has been updated with
these new changes. If you are curious about our wire protocol you can read
about it here:

https://github.com/katzenpost/katzenpost/blob/master/docs/specs/wire-protocol.txt


During the Brussels hackfest we:

   * worked on our Google Summer of Code project submission
     AND additional work on our website:
     https://katzenpost.mixnetworks.org/contribute.html
     https://github.com/katzenpost/mixnet_uprising/wiki/Project-Ideas

   * kwadronaut and I used a server on our test mixnet to test out Yawning's new Provider
     postgres database interface for spool and user authentication
     databases; Postgres is optional but it is *much* high performance
     than boltdb which has no granular transactional locks.

   * Vincent improved upon the java and python bindings to client library,
     currently this client library is known as "mailproxy"

   * Vincent wrote an android k9mail katzenpost prototype for demonstrations

   * held lengthy discussions about autoresponder based keyserver
     for the purpose of distributing client encryption keys

   * we collectively wrote rough draft specifications for autoresponder services
     known as kaetzchen and a keyserver:

       * autoresponder protocol known as kaetzchen
         https://github.com/katzenpost/katzenpost/blob/master/docs/drafts/kaetzchen.txt

       * keyserver specification (rough draft)
         https://github.com/katzenpost/katzenpost/blob/master/docs/drafts/keyserver.txt

   * masala wrote a golang CLI client:
     https://github.com/katzenpost/demotools/tree/master/cliclient

   * masala worked on making bandwidth overhead estimations of the PKI protocol:
     https://github.com/mixmasala/docs/blob/mix_bandwidth_estimation/drafts/pki-bandwidth-estimate.txt
     https://github.com/mixmasala/docs/blob/mix_bandwidth_estimation/tuning/bw.py

     Note: Bandwidth and scaling estimations is something that Nick Mathewson has
     requested in his review of our PKI specification document.

   * had conversations with several guests at our hackfest including:
      * Claudia Diaz
      * video conference with Yawning Angel
      * the developers of sequoia-pgp https://sequoia-pgp.org/
      * Harry Halpin
      * an associate of Harry who is involved in the crypto currency
        financial industry

   * Tg created NixOS packages for the katzenpost components
     https://github.com/katzenpost/nixpkgs

     and NixOS katzenpost configuration for automatic deployment
     to linux containers:
     https://github.com/katzenpost/nixops

   * meskio and kaliy: worked on a number of things, including
       * LEAP based account registration for katzenpost Providers

       * setup Prometheus to monitor our test mixnet

       * performed stress tests to determine how network
         load would be affected by various client concurrency levels and
         bandwidth usage:
         https://github.com/katzenpost/katzsim

Since the Brussels hackfest, Masala and I visited Claudia Diaz and
Tariq Elahi at KU Leuven to discuss mix network designs. In
particular we asked various questions about the AQMs used in the
Katzenpost server side and later got clarification from Yawning. We
also discussed mix network tuning and learned that the preferred
method of tuning mixnets is to run lots of simulations and use
different kinds of analysis to determine an appropriate set of tuning
parameters.

During this discussion Tariq mentioned that their simulations are
likely not using the exact same AQMs as Katzenpost server side.  We
decided that these simulations could be executed using our "mixnet
emulator" which is called kimchi. It runs an entire katzenpost mix
network and nonvoting authority in a single golang process.

We patiently await for a response to our query:
   "What features should the mixnet emulator/simulator have?"

Yawning recently implemented the keyserver:

https://github.com/katzenpost/katzenpost/blob/master/server/internal/provider/kaetzchen/keyserver.go

and the mailproxy client side for interacting with the keyserver:

https://github.com/katzenpost/mailproxy/blob/master/api_kaetzchen.go

Since then Yawning's focus has been to improve server side stability
and performance. You can see his task list here: https://github.com/orgs/katzenpost/projects/2

Masala and I have been working on writing a voting directory authority server.

Currently our test mixnet works because Yawning has not only written
most of the code but he also wrote a nonvoting Directory Authority
PKI. However, the nonvoting PKI is not suitable for production use
where a decentralized design should be used to achieve the desired
security properties.

Beyond our officially sanctioned work on this project, and in my free
time, I've been exploring other use-cases for mixnets. I've been
thinking about "strong location hiding properties". What I came up
with is a kind of kaetzchen dead drop service where you can retreive
messages from a remote Provider. The client would never directly
interact with the remote Provider but instead only uses the mixnet to
retrieve messages.

https://github.com/katzenpost/katzenpost/blob/master/docs/drafts/deaddrop.txt

Cheers!

David
