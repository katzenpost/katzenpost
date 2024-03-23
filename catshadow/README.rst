
.. image:: https://travis-ci.org/katzenpost/catshadow.svg?branch=master
  :target: https://travis-ci.org/katzenpost/catshadow

.. image:: https://godoc.org/github.com/katzenpost/katzenpost/catshadow?status.svg
  :target: https://godoc.org/github.com/katzenpost/katzenpost/catshadow


the catshadow client
====================

Catshadow is a mix network messaging system. This repository contains
a client library which can be used with a Katzenpost mix network. It
not only uses strong modern end to end encryption (Noise + Double
Ratchet), but it is also designed to reduce the amount of metadata
leaked onto the network.

This code is actively being developed and is intended
to be used with our Qt user interface, catchat:

* https://github.com/katzenpost/catchat


contact
=======

* IRC: irc.oftc.net #katzenpost <irc://irc.oftc.net/#katzenpost>
* Mailing List <https://lists.mixnetworks.org/listinfo/katzenpost>


disclaimer
==========

Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.


testing
=======

optional docker tests
---------------------

To run the optional docker tests firstly, see our docker repo
and start your local dockerized mix network:

https://github.com/katzenpost/katzenpost/docker

A couple of minutes after startup run the tests like this:
::

   GORACE=history_size=7 go test -tags=docker_test -race -v -run Docker

This will run our docker based integration tests for the catshadow library.


design
======

It is my understanding that in terms of the analysis presented in this
blog post ( Brian Warner's **"Petmail mailbox-server delivery protocol"**
http://www.lothar.com/blog/53-petmail-delivery/ ),
the catshadow messaging system can be described as:

**S1, M0, R1, Rev0**

Here I rephrase the definitions of the above messaging system
properties: Catshadow clients can compare delivery tokens to determine
if they share contacts. However the message spool server cannot tell
which message came from which sender, not even that two messages came
from the same sender, nor can it determine how many senders might be
configured for each recipient. The recipient cannot use the transport
information to identify the sender. The recipient depends upon
information not visible to the mailbox server to identify the sender,
which means a legitimate (but annoying) sender could flood the server
without revealing which sender they are. Finally, the revocation
behavior is such that the recipient can revoke one or more senders
without involving the remaining senders.

Clients make use of a Sphinx SURB based protocol to retrieve messages
from their remote spool service. The mix network has several providers
which operate spool services which clients can interact with. The
spool service is in fact a seperate process which uses our CBOR/HTTP
over unix domain socket plugin system to communicate with the mix server.

Over time I plan on replacing the spool services with gradually more
sophisticated spool services until I finally have a replicating CRDT
based spool service which can help eliminate single points of failure
in this messaging system.

Clients make use of the PANDA protocol for exchanging spool identities
and the Signal Double Ratchet keys. That is, this messaging system creates
bidirectional metadata leakage resistant communications channels which
are composed with two unidirection channels. Each unidirectional channel
contains the required information to write to a correspondant's
remote message spool.

Katzenpost is a variant of the Loopix design and as such makes use of
the Poisson mix strategy and therefore must be properly tuned. Tuning
of the Poisson mix strategy has not been publicly solved yet but I
suspect the solution has something to do with a discrete network event
simulator and possibly some machine learning algorithms as
well. Perhaps we all should consider the tuning of this mixnet
messaging system as half of its design.

Another unfinished design area is: The Catshadow client periodically
polls the client's remote message spool where the intervals between
polling are the result of a Poisson process. Currently, tuning this
Poisson procress is left unfinished, however, I can state that the
goal in tuning this would be to reduce vulnerability to a long term
statistical disclosure attack where the passive adversary or
compromised Provider tries to link clients with their spool
service.


**"The Loopix Anonymity System"**:

https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-piotrowska.pdf


the longer design overview
--------------------------

The design of this messaging is not yet fully specified but is
partially specified in these specification documents:

* https://github.com/katzenpost/katzenpost/blob/main/docs/drafts/client.md
* https://github.com/katzenpost/katzenpost/blob/main/docs/drafts/deaddrop.md
* https://github.com/katzenpost/katzenpost/blob/main/docs/drafts/decoy_traffic.md
* https://github.com/katzenpost/katzenpost/blob/main/docs/drafts/panda.md

Whereas all those specifications assume the existence of the core
Katzenpost specifications here which mostly covers the design of
the server infrastructure:

* https://github.com/katzenpost/katzenpost/blob/main/docs/specs/mixnet.md
* https://github.com/katzenpost/katzenpost/blob/main/docs/specs/wire-protocol.md
* https://github.com/katzenpost/katzenpost/blob/main/docs/specs/kaetzchen.md
* https://github.com/katzenpost/katzenpost/blob/main/docs/specs/sphinx_replay_detection.md
* https://github.com/katzenpost/katzenpost/blob/main/docs/specs/sphinx.md
* https://github.com/katzenpost/katzenpost/blob/main/docs/specs/oldspecs/end_to_end.md
* https://github.com/katzenpost/katzenpost/blob/main/docs/specs/pki.md
* https://github.com/katzenpost/katzenpost/blob/main/docs/specs/certificate.md

There is an older copy of our core Katzenpost specifications rendered
in Latex if you prefer to read it that way:
https://panoramix-project.eu/wp-content/uploads/2019/03/D7.2.pdf


code organization
=================

This repository contains a small amount of high level client
code. This client depends on lots of code in other Katzenpost
repositories including my fork of agl's PANDA and agl's Signal Double
Ratchet:

* https://github.com/katzenpost/katzenpost/doubleratchet
* https://github.com/katzenpost/katzenpost/panda
* https://github.com/katzenpost/channels
* https://github.com/katzenpost/katzenpost/memspool
* https://github.com/katzenpost/katzenpost/client
* https://github.com/katzenpost/katzenpost/minclient
* https://github.com/katzenpost/katzenpost/core

acknowledgments
===============

* I would like to thank Leif Ryge for feedback during the design of this
  client and many of its protocols.

* I would like to also thank Adam Langely for writing [Pond](https://github.com/agl/pond)
  which has very obviously inspired a few of our design choices and has provided some
  code that we use such as the PANDA cryptographic protocol and the Double Ratchet.


supported by
============

The development of the Catshadow Katzenpost client has been supported by:

* The Samsung Next Stack Zero grant
* NLnet and the NGI0 PET Fund paid for by the European Commission

.. image:: https://katzenpost.mixnetworks.org/_static/images/eu-flag-tiny.jpg


See **NLnet accouncement** https://nlnet.nl/project/katzenpost/index.html


See **Announcing the Samsung NEXT Stack Zero Grant recipients**.
https://samsungnext.com/whats-next/category/podcasts/decentralization-samsung-next-stack-zero-grant-recipients/




license
=======

AGPL: see LICENSE file for details.

Copyright (C) 2020  David Stainton.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
