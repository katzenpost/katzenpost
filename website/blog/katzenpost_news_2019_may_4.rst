.. post:: May 4, 2019
   :tags: katzenpost, blog
   :title: Katzenpost Monthly News Update
   :author: David Stainton
   :nocomments:

May 4, 2019

Katzenpost Monthly News Update
------------------------------

Greetings,

The last few weeks have been very busy. I now have the basic working
prototype implementation of a new Katzenpost messaging system. This
new system has mutual location hiding properties for communication
partners because recipients retreive their messages from a remote
spool using a Sphinx SURB based protocol. [SPHINX]_  [SPHINXSPEC]_

Naming things is tricky. I had to call it something:
https://github.com/katzenpost/katzenpost/catshadow

This messaging system is inspired by agl's pond, obviously.
See agl's pond here: https://github.com/agl/pond

I forked agl's Double Ratchet from pond:
https://github.com/katzenpost/doubleratchet

Also forked agl's PANDA:
https://github.com/katzenpost/katzenpost/panda

Communication partners use a remote spool service which is now, memspool
but later it will be a replicating CRDT:
https://github.com/katzenpost/katzenpost/memspool

In order to exchange double ratchet keys and spool identities to form
a bidirectional cryptographic channel, clients make use of the PANDA
service. That is to say, PANDA (Phrase Automated Nym Discovery
Authentication) is just another mixnet service like the memspool
service mentioned above.

The user interface I wrote is a CLI terminal interface and it really
kind of sucks. I'm feeling rather inspired by Special's golang
Ricochet. The UI and the backend are two separate processes and
communicate by unix domain socket. Cool. Maybe I should do a similar construction
that way someone else can later write a crazy C++ Gtk UI for this
thing. Although I suspect this strategy doesn't work well with
Android. Unclear. At any rate, catshadow is crash fault tolerant, I
hope. It is also internally way more simple than mailproxy and doesn't
use database transactions or anything like that. State is persisted to
disk in an encrypted statefile... passphrase, argon2, nacl secretbox of course.

Anyway describing this whole thing is basically a paper worth of words
which I shall attempt to articulate later. The overall strategy for
Katzenpost should be for this client to merely serve as a
demonstration. Whereas it would be far better to help another software
project integrate with Katzenpost.  Projects such as Briar and Wire
come to mind. That having been said, I'd like to soon start a
volunteer operated Katzenpost mix network so that we have some real
infrastructure that allows us to start using catshadow to send each
other encrypted messages. The amount of metadata we leak onto the
network will depend on how many people use the system, number of mixes
and of course how it is tuned. Since tuning is currently an unsolved
problem, it's all just a fun game anyway.

OK folks that's all for now. I am not sure exactly what the next steps
should be and I'm planning on deliberating while I discuss it with my
colleagues and advisors.  Either I will start a demo mixnet all on one
machine that we can use to try out catshadow or I will attempt to
instigate a volunteer operated mixnet. Things will get very cool once
we have multiple applications that can use the mixnet. :)


Cheers,

David


.. [SPHINX]  Danezis, G., Goldberg, I., "Sphinx: A Compact and
             Provably Secure Mix Format", DOI 10.1109/SP.2009.15,
             May 2009, <https://cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf>.

.. [SPHINXSPEC] Angel, Y., Danezis, G., Diaz, C., Piotrowska, A., Stainton, D.,
                "Sphinx Mix Network Cryptographic Packet Format Specification"
                July 2017, <https://github.com/katzenpost/katzenpost/blob/master/docs/specs/sphinx.rst>.
