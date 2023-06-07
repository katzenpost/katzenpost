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

The katzenpost monorepo now has a copy of the sphincsplus git repo in `katzenpost/sphincsplus/ref`
and in that location we've added some cgo bindings which require this bash
environment variable to be set in order to compile:

.. code-block:: bash

  export CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f"

The Katzenpost fork of the sphincs+ ref code was created so that we
could make some necessary changes to the Makefile. However after a
while of using it we realized we also needed to change a few things to
get our cgo bindings to work.


supported by
============

.. image:: https://katzenpost.mixnetworks.org/_static/images/eu-flag-tiny.jpg

This project has received funding from:

* European Union’s Horizon 2020 research and innovation programme under the Grant Agreement No 653497, Privacy and Accountability in Networks via Optimized Randomized Mix-nets (Panoramix).
* The Samsung Next Stack Zero grant
* NLnet and the NGI0 PET Fund paid for by the European Commission
