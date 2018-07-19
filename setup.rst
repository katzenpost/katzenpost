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

Synchronize Clock
=================

Each network component, the PKI and mixes/providers,
MUST have the correct time. We recommend
`chrony <https://chrony.tuxfamily.org/>`_ for the purpose of time synchronization.

.. code:: console

    apt install chrony


Set up the PKI
==============

Configure the PKI (or :term:`Network Authority`) based on an `example configuration file <https://github.com/Katzenpost/daemons/blob/master/authority/nonvoting/authority.toml.sample>`_:

.. code:: console

    wget -O authority.toml https://raw.githubusercontent.com/katzenpost/daemons/master/authority/nonvoting/authority.toml.sample

You need to edit at least the `[Authority]` section, and configure the address(es) the authority should bind to (`Addresses`) as well as its data directory (`DataDir`).

Now, you can generate the authority identity key::

    $GOPATH/bin/nonvoting -f authority.toml -g

This `-g` option causes the :term:`Authority` server to generate an authority identity key
which will get written to the specified data directory and printed in the log.
This :term:`Authority Identity key` is used in the mix configuration file and allows
mixes interact with the PKI.

In the next step, we will set up at least one :term:`Provider` and some
:term:`Mix` nodes, and add their public identity keys to the authority before we run it.

Set up the Mixes
================

Configure the mix nodes. A sample configuration can be found here: https://raw.githubusercontent.com/Katzenpost/daemons/master/server/katzenpost.toml.sample

Generate the key::

    $GOPATH/bin/server -f katzenpost.toml -g

The generated :term:`Mix Identity key` must be added into the Authority configuration file.
Once the Authority is configured with all of the mix identity keys you can start the
Authority server and then start all the mixes.

Optional Provider Postgres Setup
================================

.. code:: console

          # requires postgres 9.5 or later
          # if you are still using Debian jessie you
          # can get postgres 9.6 from backports
          # e.g. apt install -t jessie-backports postgresql
          apt install postgresql

          # pg_hba.conf
          # The pg_hba.conf file is the place to configure access to the
          # databases. It's parsed from top to bottom, first matching rule is
          # applied. You probably need to add a rule for your 'provider' user
          # fairly early.

          # as the postgres user run these commands
          # or su - postgres if without sudo
          sudo -u postgres

          # Add the database user "provider"
          createuser -U postgres provider

          # and a database
          createdb -U postgres -O provider katzenpost

          # set some passwords for your new user
          psql
          postgres=# ALTER USER provider WITH PASSWORD 'secrətp0stgre5sy';

          # test if you can connect
          psql -U provider -h 127.0.0.1 katzenpost

          # If all goes fine, it's time to load the SQL, that script lives in
          # internal/sqldb/create_database-postgresql.sql
          psql -U provider --password -d katzenpost -h 127.0.0.1 -f create_database-postgresql.sql

          # start katzenpost server...

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
