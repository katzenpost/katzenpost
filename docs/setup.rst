How to Set Up Your Own Katzenpost Mixnet
****************************************

.. warning::

    Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.


.. caution::

    Mix networks are meant to be decentralized and therefore should
    be operated by multiple entities. You can of course be the only
    operator of a mix network for testing purposes.

build software
==============

A Katzenpost mix network has two binary programs, a :term:`PKI` and a
:term:`Mix`/:term:`Provider`.

Katzenpost server side requires golang 1.8 or later.
See golang install instructions:
https://golang.org/doc/install

The Katzenpost minclient library requires golang 1.9 or later.

You can build this software on your computer and copy
the binaries to the server from ``$GOPATH/bin``::

    go get -u -v github.com/katzenpost/daemons/authority/nonvoting
    go get -u -v github.com/katzenpost/daemons/server

The produced binaries are statically linked, so you can build the
authority and the server code on one machine, and then distribute
them to any Linux based machines to run.

get clock on sync
=================

Each network component, the PKI and mixes/providers
MUST have the correct time. We recommend installing
chrony for the purpose of time synchronization.

.. code:: console

    apt install chrony


Set up the PKI
==============

Configure the PKI (or :term:`Network Authority`) based on an `example configuration file <https://github.com/Katzenpost/daemons/blob/master/authority/nonvoting/authority.toml.sample>`_:

.. code:: console

    wget -O authority.toml https://raw.githubusercontent.com/katzenpost/daemons/master/authority/nonvoting/authority.toml.sample

You need to edit at least the `[Authority]` section, and configure the address(es) the authority should bind to (`Addresses`) as well as its data directory (`DataDir`)..

Now, you can generate the authority identity key::

    $GOPATH/bin/nonvoting -f authority.toml -g

This `-g` option causes the :term:`Authority` server to generate an authority identity key
which will get written to the specified data directory and printed in the log.
This :term:`Authority Identity key` is used in the mix configuration file and allows
mixes interact with the PKI.

In the next step, we will set up at least one :term:`Provider` and some
:term:`Mix` nodes, and add their public identity keys to the authority before we run it.

Set up the Mix
==============

Configure the mix node: https://raw.githubusercontent.com/Katzenpost/daemons/master/server/katzenpost.toml.sample

Generate the key::

    $GOPATH/bin/server -f katzenpost.toml -g

The generated :term:`Mix Identity key` MUST be entered into the PKI configuration file.
Once the PKI is configured with all of the mix identity keys you can start the
PKI server and then start all the mixes.

Add Users to the Provider
=========================

Add :term:`User`\s to the :term:`Provider` using the management interface:

.. code:: console

    socat unix:/<path-to-data-dir>/management_sock STDOUT
    ADD_USER alice X25519_public_key_in_hex_or_base64

Run the Authority
=================

.. code:: console

    $GOPATH/bin/nonvoting -f authority.toml
