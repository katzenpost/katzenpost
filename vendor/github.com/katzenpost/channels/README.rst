
.. image:: https://travis-ci.org/katzenpost/channels.svg?branch=master
  :target: https://travis-ci.org/katzenpost/channels

.. image:: https://godoc.org/github.com/katzenpost/channels?status.svg
  :target: https://godoc.org/github.com/katzenpost/channels

Channels Library
================

Katzenpost Mix Network Cryptographic communication channels library.
This library is meant to be used with our Katzenpost client library: https://github.com/katzenpost/client
and a Katzenpost mix network that has at least one memspool instance running: https://github.com/katzenpost/memspool

This library contains three channels:

* unreliable remote spool channel
* unreliable Noise X
* unreliable Double Ratchet

The Noise X and Double Ratchet channels both make use of the remote spool channel. That is to say,
we want to communicate with remote spools over our mix network. If we didn't use
spools then the other party would be required to be online at the same time as our client. The above
three channel types have differing use cases. Noise X is useful because it's nonce ensures each ciphertext
it produces is different even if message input was the same as a previous operation. We can use this
feature of the Noise X channel to ensure that we don't leak retransmissions from applications that
may retransmit an identical payload. Egress Providers on a Katzenpost mix network get to see the payload.
This is one reason why end to end encryption must always be used. The remote spool channel is intended
to be used by applications that already implement their own end to end encryption.


TODO
----

* publish-subscribe channels where clients can send the remote service
  some SURBs and then await replies from the remote subscription spool feed.
* optional reliable channels using a custome ARQ protocol scheme


license
=======

AGPL: see LICENSE file for details.
