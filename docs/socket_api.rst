Catshadow Plugin System
***********************

| David Stainton
| an anonymous cipherpunk

Version 0

.. rubric:: Abstract

This document describes a mixnet client plugin system, specifically
the design is meant to be implemented by the catshadow katzenpost client.


.. contents:: :local:


1. Introduction
===============

The catshadow client will run a listener on a Unix domain socket which
allows control over the client. This protocol allows for the user
interface to run in a different process and possibly be sandboxed. This is
meant as the only native interface for controlling the catshadow client.


2. Rough sketch of the API design
=================================

**SUBSCRIPTION QUEUES**

- contact update::

  { updateID, contact, state[ PENDING | FAILED | DONE ] }

- inbox update::

    { inboxID, contact, payload }

- outbox update::

  { outboxID, state [outbox | transmitted | acked] }


**APP API**

- send message: contact ; payload ; outboxID
- delete message: inboxID
- delete contact update: updateID
- add contact: name ; passphrase
- delete contact: name
- cancel outbox message: { outboxID }
