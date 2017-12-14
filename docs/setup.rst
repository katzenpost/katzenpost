How to Set Up Your Own Katzenpost Mixnet
****************************************

introduction
============

Mix networks are meant to be decentralized and therefore should
be operated by multiple entities. You can of course be the only
operator of a mix network for testing purposes.

build software
==============

A Katzenpost mix network has two binary programs, a PKI and a
mix/provider. You can build this software on your computer and copy
the binaries to the server from $GOPATH/bin::

    go get github.com/katzenpost/daemons/authority/nonvoting
    go get github.com/katzenpost/daemons/server


get clock on sync
=================

Each network component, the PKI and mixes/providers
MUST have the correct time. We recommend installing
chrony for the purpose of time synchronization.

.. code:: console

    apt install chrony


generate the PKI key
====================

Configure the PKI, an example configuration can be found here:

https://github.com/Katzenpost/daemons/blob/master/authority/nonvoting/authority.toml.sample


.. code:: console

    ./nonvoting -f authority.toml -g

This `-g` option causes the authority server to generate an authority identity key
which will get written to the specified data directory and printed in the log.
This Authority Identity key is used in the mix configuration file and allows
mixes interact with the PKI.

Without the `-g` option for running the Authority
.. code:: console

    ./nonvoting -f authority.toml

add users to the provider
=========================

Add users to the Provider using the management interface:

.. code:: console

    socat unix:/home/pano/node/data/management_sock STDOUT
    ADD_USER alice X25519_public_key_in_hex_or_base64

set up the mix
==============

Configure the mix node: https://raw.githubusercontent.com/Katzenpost/daemons/master/server/katzenpost.toml.sample

Generate the key
.. code:: console

    ./server -f katzenpost.toml -g

The generated mix identity key MUST be entered into the PKI configuration file.
Once the PKI is configured with all of the mix identity keys you can start the
PKI server and then start all the mixes.
