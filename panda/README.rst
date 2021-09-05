

.. image:: https://travis-ci.org/katzenpost/panda.svg?branch=master
  :target: https://travis-ci.org/katzenpost/panda

.. image:: https://godoc.org/github.com/katzenpost/katzenpost/panda?status.svg
  :target: https://godoc.org/github.com/katzenpost/katzenpost/panda

PANDA Library
=============

PANDA stands for Phrase Automated Nym Discovery Authentication, which
is a protocol variation of EKE2, a PAKE, Password Authenticated Key
Exchange, with some design variations that allows clients to perform
the key exchanges asynchronously using a ciphertext intermediary.


Status
======

This is currently in a draft development state due to
pending feature addition to our mix server library to add
a mixnet service plugin system.


license
=======

AGPL: see LICENSE file for details.


supported by
============

.. image:: https://katzenpost.mixnetworks.org/_static/images/eu-flag-tiny.jpg

This project has received funding from the European Union’s Horizon 2020
research and innovation programme under the Grant Agreement No 653497, Privacy
and Accountability in Networks via Optimized Randomized Mix-nets (Panoramix).


acknowledgements
================

Thanks to Adam Langley for writing the original PANDA library which this is based on.
Adam's implementation can be found here:

* https://github.com/agl/pond/tree/master/panda
