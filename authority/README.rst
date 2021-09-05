

.. image:: https://travis-ci.org/katzenpost/authority.svg?branch=master
  :target: https://travis-ci.org/katzenpost/authority

.. image:: https://godoc.org/github.com/katzenpost/katzenpost/authority?status.svg
  :target: https://godoc.org/github.com/katzenpost/katzenpost/authority


Katzenpost Directory Authority
==============================

Katzenpost has two directory authority servers; a voting and nonvoting server.
The voting server's design is specified in the **"Katzenpost Mix Network Public Key Infrastructure Specification"** https://github.com/katzenpost/katzenpost/blob/master/docs/specs/pki.rst


Building
--------

Requires golang 1.11 or later. Dependencies pinned using go-modules.
For more info about go-modules, see: https://github.com/golang/go/wiki/Modules

Build the mix server like this:
::

  export GO111MODULE=on
  cd cmd/voting # (or cmd/nonvoting)
  go build


license
=======

AGPL: see LICENSE file for details.


supported by
============

.. image:: https://katzenpost.mixnetworks.org/_static/images/eu-flag-tiny.jpg

This project has received funding from the European Union’s Horizon 2020
research and innovation programme under the Grant Agreement No 653497, Privacy
and Accountability in Networks via Optimized Randomized Mix-nets (Panoramix).
