Downloads
*********

A Katzenpost network can (and should) be "tuned" to its use case. Example use cases are "instant messaging", "cryptocurrency transactions", "e-mail" etc.

Playground Binaries
===================

The current playground demonstrates the use of a Katzenpost mixnet "for e-mail": Users can register with our playground "providers", and then use a local SMTP and POP3 proxy to send and receive messages with whatever mail client they want.

The Android demo shows how to use the mailproxy API to more tightly integrate Katzenpost with a mail client, in this case K-9 Mail. It is not and is not meant to become a full-fledged client. We believe "e-mail" is not the right basis for a nice, modern messaging client.

.. warning::

   This release of the Katzenpost mailproxy is preconfigured to use our public test mix network. Expect this to break and require frequent updates. Debug logs are publicly available and this testbed is fully controlled by us, so it **DOES NOT PROVIDE ANY ANONYMITY WHATSOEVER and is purely for testing**.

* `Playground mailproxy client for Linux/Mac <https://github.com/katzenpost/playground/releases>`_
* `Playground demo client for Android (based on K-9 Mail) <https://play.google.com/store/apps/details?id=horse.amazin.my.l10>`_
* `Playground Instructions <https://github.com/katzenpost/playground/blob/master/README.rst>`_
* `Playground Network Debug Log Viewer <http://logviewer.katzenpost.mixnetworks.org/>`_

Client build instructions
=========================

* `Handbook <https://katzenpost.mixnetworks.org/docs/handbook/>`_
* `Getting started with Katzenpost development <https://katzenpost.mixnetworks.org/docs/HACKING/>`_

Server
======

* See https://katzenpost.mixnetworks.org/docs/setup.html
