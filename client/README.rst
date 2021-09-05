
.. image:: https://travis-ci.org/katzenpost/client.svg?branch=master
  :target: https://travis-ci.org/katzenpost/client

.. image:: https://godoc.org/github.com/katzenpost/katzenpost/client?status.svg
  :target: https://godoc.org/github.com/katzenpost/katzenpost/client


Katzenpost Mix Network Client Library
=====================================

This client library is general purpose in the sense that it can be used to
build arbitrarily complex messaging systems using Katzenpost. However note that
right now it only supports strict SURB based query response protocols to
interactive mix network services. These services can be written in any langauge
and plugged into the Providers. Furthermore this client does not yet perform
any retransmissions if a packet gets dropped by the mix network.

travis tests
------------

Travis tests may sometimes fail if they take too long.


gitlab CI tests
---------------

Our gitlab tests are located here:

https://gitlab.techcultivation.org/katzenpost/client/-/jobs


optional docker tests
---------------------

To run the optional docker tests firstly, see our docker repo
and start your local dockerized mix network:

https://github.com/katzenpost/katzenpost/docker

A couple of minutes after startup run the tests like this:
::

   GORACE=history_size=7 go test -tags=docker_test -race -v -run Docker


license
=======

AGPL: see LICENSE file for details.


supported by
============

.. image:: https://katzenpost.mixnetworks.org/_static/images/eu-flag-tiny.jpg

This project has received funding from the European Union’s Horizon 2020
research and innovation programme under the Grant Agreement No 653497, Privacy
and Accountability in Networks via Optimized Randomized Mix-nets (Panoramix).
