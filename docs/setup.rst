How to Set Up Your Own Katzenpost Mixnet
****************************************

For now, this is a lazy copy of https://pad.riseup.net/p/katzenpost-deploy and totally WIP...

build software
==============
You can build the software in your computer and copy the binaries to the server from $GOPATH/bin::

    go get github.com/katzenpost/daemons/authority/nonvoting
    go get github.com/katzenpost/daemons/server

generate the PKI key
====================

Configure the PKI: https://github.com/Katzenpost/daemons/blob/master/authority/nonvoting/authority.toml.sample

.. code:: console

    ./nonvoting -f authority.toml -g

This causes the authority server to generate an authority identity key
which will get written to the specified data directory and printed in the log.
This Authority Identity key is used in the mix configuration file.

Without the `-g` option for running the Authority::

    ./nonvoting -f authority.toml


set up the provider
===================

set up the mix
==============

Configure the mix node: https://raw.githubusercontent.com/Katzenpost/daemons/master/server/katzenpost.toml.sample

Generate the key::
    ./server -f katzenpost.toml -g

Copy the key into the P


get clock on sync
=================

.. code:: console

    apt install chrony


add users to the provider
=========================

Let's connect to the managment interface of the PKI::

    $ socat unix:/home/pano/node/data/management_sock STDOUT
    ADD_USER alice keymaterial
