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

Katzenpost now uses hybrid post quantum with classical cryptographic
protocols. As part of this change in our cryptographic protocols we
have added the use of Sphincs+, the stateless hash based post quantum
signature scheme.

The katzenpost monorepo now has a copy of the sphincsplus reference
git repo in `katzenpost/sphincsplus/ref` and in that location we've
added some cgo bindings which require this bash environment variable
to be set in order to compile:

.. code-block:: bash

  export CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f"


Install optional CTIDH dependency:

.. code-block:: bash

		git clone https://github.com/katzenpost/ctidh_cgo.git
		cd ctidh_cgo
		git clone https://codeberg.org/io/highctidh.git
		cd highctidh
		make libhighctidh_511.so libhighctidh_512.so libhighctidh_1024.so libhighctidh_2048.so
		sudo make install
		cd ..
		export P=`pwd`
		export CTIDH_BITS=1024
		cp ${P}/binding${CTIDH_BITS}.h ${P}/binding.h
		export CGO_CFLAGS="-g -I${P} -I${P}/highctidh -DBITS=${CTIDH_BITS}"
		export CGO_LDFLAGS="-L${P}/highctidh -Wl,-rpath,${P}/highctidh -lhighctidh_${CTIDH_BITS}"


Run CTIDH NIKE tests:

.. code-block:: bash

		cd katzenpost/core/crypto/nike/ctidh
		go test -v -tags ctidh


supported by
============

.. image:: https://katzenpost.mixnetworks.org/_static/images/eu-flag-tiny.jpg

This project has received funding from:

* European Union’s Horizon 2020 research and innovation programme under the Grant Agreement No 653497, Privacy and Accountability in Networks via Optimized Randomized Mix-nets (Panoramix).
* The Samsung Next Stack Zero grant
* NLnet and the NGI0 PET Fund paid for by the European Commission
