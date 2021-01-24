Contribute to Katzenpost
************************

Communication
=============

 * IRC: irc.oftc.net #katzenpost <irc://irc.oftc.net/#katzenpost>
 * Mailing List <https://lists.mixnetworks.org/listinfo/katzenpost>

Contribution Guidelines
=======================

#. Get familiar with the various repositories on our `Github <https://www.github.com/katzenpost>`_.
#. Developers should look at the Developer Guide `docs/HACKING/index` and the Setup Guide `docs/setup` to build and run a local Katzenpost mixnet.
#. Open a pull request on Github. We will help with occurring problems and merge your changes back into the main project.

Where to Start
==============

We have a lot of repositories! The top-level packages that you'll probably want to look at first are:

 * Catchat, a QT cross-platform metadata minimizing messenger application utilizing catshadow.
   https://github.com/katzenpost/catchat

 * Catshadow is a mix network messaging system. This repository contains
   a client library which can be used with a Katzenpost mix network. It
   not only uses strong modern end to end encryption (Noise + Double
   Ratchet), but it is also designed to reduce the amount of metadata
   leaked onto the network.
   https://github.com/katzenpost/catshadow

 * Client is a mixnet client library you can use to write applications that interact with mixnet services.
   https://github.com/katzenpost/client

 * Server, the mix and provider daemons that route messages and run services.
   https://github.com/katzenpost/server

 * Authority, the PKI daemons that provide key and service information to the network.
   https://github.com/katzenpost/authority

 * Mailproxy, a POP3/SMTP proxy to use email clients with katzenpost
   https://github.com/katzenpost/mailproxy

 * Server_Plugins, simple example of a mixnet service plugins written in golang and rust
   https://github.com/katzenpost/server_plugins

Project Ideas
=============

 * See the Project-Ideas page on our wiki:
   https://github.com/katzenpost/mixnet_uprising/wiki/Project-Ideas

 * Some of our other longer term projects ideas involving future research
   are documented here in various other tickets:
   https://github.com/katzenpost/mixnet_uprising/issues
