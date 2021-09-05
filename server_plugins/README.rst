
Server Plugins
==============

Server plugins are used to extend the functionality of Providers
as described in:

**"Katzenpost Provider-side Autoresponder Extension"**
https://github.com/katzenpost/katzenpost/blob/master/docs/specs/kaetzchen.rst

Kaetzchen services are essentially simple Request/Response services
where the response is sent back to the client using a SURB.
This repository contains optional plugins for the Katzenpost mix server.

See the handbook to learn how to configure external plugins:

* https://github.com/katzenpost/katzenpost/blob/master/docs/handbook/mix_server.rst#external-kaetzchen-plugin-configuration


Status
======

The current status is that: "Everything works perfectly."

So far I've implemented an "echo service" in golang, rust and
python. Using these examples should make it clear how to write your
own plugin.

Please do let us know if you write a new plugin for Katzenpost!


license
=======

AGPL: see LICENSE file for details.


supported by
============

.. image:: https://katzenpost.mixnetworks.org/_static/images/eu-flag-tiny.jpg

This project has received funding from the European Union’s Horizon 2020
research and innovation programme under the Grant Agreement No 653497, Privacy
and Accountability in Networks via Optimized Randomized Mix-nets (Panoramix).
