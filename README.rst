

.. image:: https://travis-ci.org/katzenpost/client.svg?branch=master
  :target: https://travis-ci.org/katzenpost/client

.. image:: https://godoc.org/github.com/katzenpost/client?status.svg
  :target: https://godoc.org/github.com/katzenpost/client


Katzenpost Mix Network Client Library
=====================================


optional docker tests
---------------------

To run the option docker tests firstly, see our docker repo
and start your local dockerized mix network:

https://github.com/katzenpost/docker

A couple of minutes after startup run the following commands:
::

   GORACE=history_size=7 go test -v -tags=docker_test -race -run TestClientBlockingSendReceive
   GORACE=history_size=7 go test -v -tags=docker_test -race -run TestClientBlockingSendReceiveWithDecoyTraffic


license
=======

AGPL: see LICENSE file for details.


supported by
============

.. image:: https://katzenpost.mixnetworks.org/_static/images/eu-flag-tiny.jpg

This project has received funding from the European Union’s Horizon 2020
research and innovation programme under the Grant Agreement No 653497, Privacy
and Accountability in Networks via Optimized Randomized Mix-nets (Panoramix).
