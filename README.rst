.. image:: https://github.com/katzenpost/katzenpost/actions/workflows/go.yml/badge.svg?branch=test_add_ci
  :target: https://github.com/katzenpost/katzenpost/actions

.. image:: https://godoc.org/github.com/katzenpost/katzenpost/core?status.svg
  :target: https://godoc.org/github.com/katzenpost/katzenpost/core

Katzenpost monorepo
===================

Visit the project website for more information about Katzenpost.

https://katzenpost.mixnetworks.org/


Building from Go source
=======================

Katzenpost now uses hybrid post quantum with classical cryptographic protocols.
As part of this change in our cryptographic protocols we have added the use
of Sphincs+, the stateless hash based post quantum signature scheme.

Install this dependency like this:

```
git clone https://github.com/katzenpost/sphincsplus.git
cd sphincsplus/ref
make libsphincsplus.so
sudo make install # installs into /usr/local
sudo ldconfig
```

The Katzenpost fork of the sphincs+ ref code was created so that we could
make some necessary changes to the Makefile so that it builds .so file
and installs into `/usr/local`.


supported by
============

.. image:: https://katzenpost.mixnetworks.org/_static/images/eu-flag-tiny.jpg

This project has received funding from:

* European Union’s Horizon 2020 research and innovation programme under the Grant Agreement No 653497, Privacy and Accountability in Networks via Optimized Randomized Mix-nets (Panoramix).
* The Samsung Next Stack Zero grant
* NLnet and the NGI0 PET Fund paid for by the European Commission
