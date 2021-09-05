How to Set Up Your Own Katzenpost Mixnet
****************************************

.. warning::

    Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.


.. caution::

    Mix networks are meant to be decentralized and therefore should
    be operated by multiple entities. You can of course be the only
    operator of a mix network for testing purposes.


Build Software
==============

Take a look at our docker repo. This will explain how to configure and run a katzenpost mixnet.

* https://github.com/katzenpost/docker

A Katzenpost mix network has two binary programs, a :term:`PKI` and a
:term:`Mix`/:term:`Provider`.

Katzenpost server side requires a recent golang.
See golang install instructions:
https://golang.org/doc/install


Follow the build instructions for each Katzenpost component repo.

* https://github.com/katzenpost/server

* https://github.com/katzenpost/authority

The produced binaries are statically linked, so you can build the
authority and the server code on one machine, and then distribute
them to any Linux based machines to run.


Synchronize Clock
=================

Each network component, the PKI and mixes/providers,
MUST have the correct time. We recommend
`chrony <https://chrony.tuxfamily.org/>`_ for the purpose of time synchronization.

.. code:: console

    apt install chrony


Add Users to the Provider
=========================

This step might not need to be performed if you are using a client
that auto-registers users with their Katzenpost Provider; such as catchat.

Add :term:`User`\s to the :term:`Provider` using the management interface:

.. code:: console

    socat unix:/<path-to-data-dir>/management_sock STDOUT
    ADD_USER alice X25519_public_key_in_hex_or_base64
    
In case you want to use the automatic key discovery for mailproxy, the user identity key (identity.public.pem) also needs to be set:

.. code:: console

    SET_USER_IDENTITY alice X25519_public_key_in_hex_or_base64
