Katzenpost Voting Directory Authority
=====================================

Overview
--------

Most of the mixnet papers are written with the assumption that
the mixnet's PKI exists and performs their functions perfectly.
Our mixnet PKI is a so called Directory Authority design which is
inspired by the Tor's and Mixminion's Directory Authority.


For more details about the design of the Katzenpost voting PKI
you should see our specification document:

* https://github.com/katzenpost/docs/blob/master/specs/pki.rst


As with Katzenpost clients and mixes, this authority server uses our
post quantum cryptographic noise based wire protocol as described
in the specification document:

* https://github.com/katzenpost/docs/blob/master/specs/wire-protocol.rst

Each authority's configuration has the public link layer key
of each of it's peers for authenticating the wire protocol connection.

Peers are also configured with each other's public signing key so that they
may verify each other's signatures on votes. The voting system is used to
create a document describing the collective view of the network. Mixnet clients
download the consensus document so that they may utilize the network to route
their Sphinx packets.

Install a release
-----------------

The daemons release contains the voting authority server
and can be found here:

* https://github.com/katzenpost/daemons/releases


Building The Voting Directory Authority from source
---------------------------------------------------

Building from source has the following prerequisites:

* Some familiarity with building Go binaries.
* `Go <https://golang.org>`_ 1.10 or later.
* A recent version of `dep <https://github.com/golang/dep>`_.


The directory authority library git repository lives here:

* https://github.com/katzenpost/authority

However our ``daemons`` git repository uses dependency vendoring.
Therefore to build from source using vendoring do this::

  cd $GOPATH/src/github/katzenpost
  git clone https://github.com/katzenpost/daemons.git
  cd daemons
  dep ensure -v
  cd authority/voting
  go build


CLI usage of The Voting Directory Authority
-------------------------------------------

The voting authority has the following commandline usage::

   ./voting -h
   Usage of ./voting:
     -f string
           Path to the authority config file. (default "katzenpost-authority.toml")
     -g    Generate the keys and exit immediately.

The ``-g`` option is used to generate the public and private signing and link keys.
