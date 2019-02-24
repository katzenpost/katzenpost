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


Configuring The Voting Directory Authority
----------------------------------------------

A sample configuration file can be found in our daemons repository, here:

* https://github.com/katzenpost/daemons/blob/master/authority/voting/authority.toml.sample

Generating configuration files and keys for a set of voting authorities can be done with the genconfig tool:

* https://github.com/katzenpost/tools/genconfig

The ``tools`` repo uses the same dependency vendoring as the ``daemons`` repo. See instructions there for using ``go dep``.

The genconfig tool has the following commandline usage::

     ./genconfig -help
     Usage of ./genconfig:
       -b string
         	Path to use as baseDir option
       -n int
         	Number of mixes. (default 6)
       -nv int
         	Generate voting configuration (default 3)
       -p int
         	Number of providers. (default 2)
       -v	Generate voting configuration

The configuration files and keys are placed in a directory structure under the baseDir::
     user@katz:~/go/src/github.com/katzenpost/tools/genconfig$ ./genconfig -b mixnet -v
     user@katz:~/go/src/github.com/katzenpost/tools/genconfig$ ls mixnet/
     authority-0  authority-2  node-1  node-3  node-5      provider-1
     authority-1  node-0       node-2  node-4  provider-0
     user@katz:~/go/src/github.com/katzenpost/tools/genconfig$ ls mixnet/authority-0
     authority-0.example.org.toml  identity.private.pem  identity.public.pem

The configuration files are defaulted with loopback addresses so that a local testing mixnet can be run; if you want to run the mixnet on several computers you will need to edit the ``DataDir``, ``Addresses`` and likely ``Identifier`` entries in each configuration file.
As absolute paths to the ``DataDir`` are required, the configuration structure produced by ``genconfig`` is not portable.

Authority section
`````````````````

The Authority section contains information which is mandatory,
for example::

  [Authority]
    Addresses = [ "192.0.2.1:29483", "[2001:DB8::1]:29483" ]
    DataDir = "/var/lib/katzenpost-authority"

* ``Addresses`` contains one or more IP addresses which
  correspond to local network interfaces to listen for connections on.
  These can be specified as IPv4 or IPv6 addresses.

* ``DataDir`` specifies the absolute path to the server's
  state files including the keypair use to sign network consensus
  documents.


Logging section
```````````````

The logging section controls the logging, for example::

  [Logging]
    Disable = false
    File = "/var/log/katzenpost.log"
    Level = "DEBUG"

* ``Disable`` is used to disable logging if set to ``true``.

* ``File`` specifies the file to log to. If omitted then stdout is used.

* ``Debug`` may be set to one of the following:

* ERROR
* WARNING
* NOTICE
* INFO
* DEBUG


Parameters section
``````````````````

The Parameters section holds the network parameters, for example::

  [Parameters]
    SendRatePerMinute = 30
    MixLambda = 0.00025
    MixMaxDelay = 90000
    SendLambda = 15.0
    SendShift = 3
    SendMaxInterval = 3000
    MixLoopLambda = 0.00025
    MixLoopMaxInterval = 90000

* ``SendRatePerMinute`` is the rate limiter maximum allowed rate of
  packets per client.

* ``MixLambda`` is the inverse of the mean of the exponential
  distribution that the Sphinx packet per-hop mixing delay will be
  sampled from.

* ``MixMaxDelay`` is the maximum Sphinx packet per-hop mixing
  delay in milliseconds.

* ``SendLambda`` is the inverse of the mean of the exponential
  distribution that clients will sample to determine intervals
  for sending forward and loop messages.

* ``SendMaxInterval`` is the maximum send interval in milliseconds.

* ``MixLoopLambda`` is the inverse of the mean of the exponential
  distribution that mixes will sample to determine the intervals
  for sending decoy loops.

* ``MixLoopMaxInterval`` is the maximum send interval in milliseconds.


Debug Section
`````````````

* ``IdentityKey`` is this authority's EdDSA signing key, in either Base16 OR Base64 format.

* ``LinkKey`` is this authority's ECDH link layer key, in either Base16 OR Base64 format.

* ``Layers`` is the number of non-provider layers in the network topology.

* ``MinNoderPerLayer`` is the minimum number of nodes per layer required to form a valid Document.

* ``GenerateOnly`` if set to true causes the server to halt and clean up the data dir
  right after long term key generation.


Mixes Section
`````````````

The Mixes configuration section looks like this
::

  [[Mixes]]
    IdentityKey = "kAiVchOBwHVtKJVFJLsdCQ9UyN2SlfhLHYqT8ePBetg="

  [[Mixes]]
    IdentityKey = "900895721381C0756D28954524BB1D090F54C8DD9295F84B1D8A93F1E3C17AD8"

* ``IdentityKey`` is the node's EdDSA signing key, in either Base16 OR Base64 format.


Providers Section
`````````````````

Configure like so:
::

   [[Providers]]
     Identifier = "example.com"
     IdentityKey = "0AV1syaCdBbm3CLmgXLj6HdlMNiTeeIxoDc8Lgk41e0="

* ``Identifier`` is the human readable provider identifier, such as a FQDN.

* ``IdentityKey`` is the provider's EdDSA signing key, in either Base16 OR Base64 format.
