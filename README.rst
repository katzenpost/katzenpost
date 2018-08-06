
Server Plugins
==============

Server plugins are used to extend the functionality of Providers
as described in:

**"Katzenpost Provider-side Autoresponder Extension"**
https://github.com/katzenpost/docs/blob/master/specs/kaetzchen.rst

Kaetzchen services are essentially simple Request/Response services
where the response is sent back to the client using a SURB.
This repository contains optional plugins for the Katzenpost mix server.

See the handbook to learn how to configure external plugins:

* https://github.com/katzenpost/docs/blob/master/handbook/index.rst#external-kaetzchen-plugin-configuration


Status
======

Currently the external plugins feature branch has NOT yet been merged
into master of the server repo:

* https://github.com/katzenpost/server/pull/63


So far I've implemented an "echo service" in golang, rust and
python. Using these examples should make it clear how to write your
own plugin.

Please do let us know if you write a new plugin for Katzenpost!


license
=======

AGPL: see LICENSE file for details.
