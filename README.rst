

.. image:: https://travis-ci.org/katzenpost/server.svg?branch=master
  :target: https://travis-ci.org/katzenpost/server

.. image:: https://godoc.org/github.com/katzenpost/server?status.svg
  :target: https://godoc.org/github.com/katzenpost/server

Server Library
==============

To build the server see the 'daemons' repo:

https://github.com/Katzenpost/daemons


Building
========

Note that some of our dependencies use ``gopkg.in`` as their import host
and this can cause you problems if you use the ``go get`` tool to install
dependencies. See this issue https://github.com/kataras/iris/issues/605
for more information. tl,dr; workaround -->
::

   git config --global http.https://gopkg.in.followRedirects true


license
=======

AGPL: see LICENSE file for details.


supported by
============

.. image:: https://katzenpost.mixnetworks.org/_static/images/eu-flag-tiny.jpg

This project has received funding from the European Union’s Horizon 2020
research and innovation programme under the Grant Agreement No 653497, Privacy
and Accountability in Networks via Optimized Randomized Mix-nets (Panoramix).
