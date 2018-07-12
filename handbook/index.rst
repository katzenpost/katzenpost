
Katzenpost Handbook
*******************

| David Stainton

Version 0

.. rubric:: Abstract

Thank you for interest in Katzenpost! This document describes how to
use and configure the Katzenpost Mix Network software system. The
target audience for this document is systems administrators and
assumes you are familiar with using the git revision control system
and building golang binaries.

.. contents:: :local:


Introduction
============

Katzenpost can be used as a message oriented transport for a variety
of applications and is in no way limited to the e-mail use case. Other
possible applications of Katzenpost include but are not limited to:
instant messenger applications such as Signal and Whatsapp, crypto
currency transaction transport, bulletin board systems, file sharing
and so forth.

The Katzenpost system has four component categories:

* public key infrastructure
* mixes
* providers
* clients

This handbook will describe how to use and deploy each of these.
The build instructions in this handbook assume that you have a proper
golang environment with at least golang 1.9 or later AND the git
revision control system commandline installed.


Building the latest stable version of Katzenpost
------------------------------------------------

NOTE: Find out what our latest stable version tag
by looking at the "releases.rst" file in the top-level
of this repository.


0. Acquire a recent version of dep: https://github.com/golang/dep

1. Clone the Katzenpost daemons repository::

     mkdir $GOPATH/github.com/katzenpost
     git clone https://github.com/katzenpost/daemons.git

2. Checkout the latest stable release tag::

     cd $GOPATH/github.com/katzenpost/daemons
     git checkout v0.0.1

2. Fetch the Katzenpost vendored dependencies::

     dep ensure

3. Build the binaries::

     cd authority/nonvoting; go build
     cd server; go build
     cd mailproxy; go build


The Katzenpost Configuration File Format
----------------------------------------

Each Katzenpost component has a configuration file in the TOML format.
This handbook will give you all the details you need to know to configure
each of these configuration files. To learn more about the TOML format
see: https://github.com/toml-lang/toml#toml

NOTE: ``#`` may be used at the beginning of a line to denote a comment
instead of an effective configuration line.


Example Katzenpost Configuration Files
--------------------------------------

Sample Katzenpost configuration files are located in our ``daemons``
git repository under the component's corresponding subdirectory:

* https://github.com/katzenpost/daemons


Notes on Building a Test Mix Network
------------------------------------

Providers, mixes and the Directory Authority are distinct components
of a Katzenpost mix network which SHOULD be deployed on separate
server machines. If you are building a test network on a single
machine then all mix network components must have differing network
endpoints; that is, if their IP addresses do not differ then their TCP
port numbers must be different.


Katzenpost Mix Network Public Key Infrastructure
================================================

Overview
--------

Currently Katzenpost has one PKI system that is ready for deployment;
the non-voting Directory Authority. Whether or not this should be used
on a production system depends on your threat model. This is
essentially a single point of failure. If this PKI system becomes
compromised by an adversary it's game over for anonymity and security
guarantees.

The Katzenpost voting Directory Authority system is a replacement for
the non-voting Directory Authority and is actively being developed.
However it's votiing protocol is NOT byzantine fault tolerant.
Therefore a Directory Authority server which is participating in the
voting protocol can easily perform a denial of service attack for each
voting round. This would cause the mix network to become totally
unusable.

Future development efforts will include designing and implementing one
or more byzantine fault tolerant PKI systems for Katzenpost.

All Katzenpost PKI systems have two essential components:

* a client library
* server infrastructure

Furthermore this client library has two types of users, namely mixes
and clients. That is, mixes must use the library to upload/download
their mix descriptors and clients use the library to download a
network consensus document so that they can route messages through the
mix network.


Building The Non-voting Directory Authority
-------------------------------------------

The easiest way to build the nonvoting Authority server is with
this single commandline::

   go get github.com/katzenpost/daemons/authority/nonvoting

However you can of course use git to clone all of our git
repositories and dependencies. You may then build the
nonvoing authority as follows::

   cd $GOPATH/github.com/katzenpost/daemons/authority/nonvoting
   go build

Neither of these build strategies is ideal because the latest
versions of any of our software dependencies may make breaking
changes. We therefore recommend using our golang vendoring system
to perform the build as described above.


CLI usage of The Non-voting Directory Authority
-----------------------------------------------

The non-voting authority has the following commandline usage::

   ./nonvoting --help
   Usage of ./nonvoting:
     -f string
           Path to the authority config file. (default "katzenpost-authority.toml")
     -g    Generate the keys and exit immediately.


The ``-g`` option is used to generate the public and private keys for
the Directory Authority.  Clients of the PKI will use this public key
to verify retreived network consensus documents.  However before
invoking the authority with this commandline option you MUST provide a
valid configuration file. This file will specify a data directory
where these keys will be written.  Normal invocation will omit this
``-g`` option because the keypair should already be present.

A minimal configuration suitable for using with this ``-g`` option for
generating the key pair looks like this::

  [Authority]
  Addresses = [ "192.0.2.1:12345" ]
  DataDir = "/var/run/katzauth"

Example invocation commandline::

   ./nonvoting -g -f my_authority_config.toml

However the invocation may fail if the permissions on the data directory
are not restricted to the owning user::

   ./nonvoting -g -f my_authority_config.toml
   Failed to spawn authority instance: authority: DataDir '/var/run/katzauth' has invalid permissions 'drwxr-xr-x'

Fix permissions like so::

   chmod 700 /var/run/katzauth

A successful run will print output that looks like this::

  14:47:43.141 NOTI authority: Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.
  14:47:43.142 NOTI authority: Authority identity public key is: 375F00F6EA20ACFB3F4CDCA7FDB50AE427BF02035B6A2F5789281DAA7290B2BB


Configuring The Non-voting Directory Authority
----------------------------------------------

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

* ``File`` specifies the file to log to. If ommited then stdout is used.

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
    MixLambda = 0.00025
    MixMaxDelay = 90000
    SendLambda = 15.0
    SendShift = 3
    SendMaxInterval = 3000

* ``MixLambda`` is the inverse of the mean of the exponential
  distribution that the Sphinx packet per-hop mixing delay will be
  sampled from.

* ``MixMaxDelay`` is the maximum Sphinx packet per-hop mixing
  delay in milliseconds.

* ``SendLambda`` is the inverse of the mean of the exponential
  distribution that clients will sample to determine send timing.

* ``SendShift`` is the shift applied to the client send timing samples
  in milliseconds.

* ``SendMaxInterval`` is the maximum send interval in milliseconds,
  enforced prior to (excluding) SendShift.


Mixes section
`````````````

The Mixes array defines the list of white-listed non-provider nodes,
for example::

  [[Mixes]]
  IdentityKey = "kAiVchOBwHVtKJVFJLsdCQ9UyN2SlfhLHYqT8ePBetg="

  [[Mixes]]
  IdentityKey = "900895721381C0756D28954524BB1D090F54C8DD9295F84B1D8A93F1E3C17AD8"


* ``IdentityKey`` is the node's EdDSA signing key, in either Base16 OR Base64 format.


Provider section
````````````````

The Providers array defines the list of white-listed Provider nodes,
for example::

  [[Providers]]
  Identifier = "provider1"
  IdentityKey = "0AV1syaCdBbm3CLmgXLj6HdlMNiTeeIxoDc8Lgk41e0="

  [[Providers]]
  Identifier = "provider2"
  IdentityKey = "375F00F6EA20ACFB3F4CDCA7FDB50AE427BF02035B6A2F5789281DAA7290B2BB"


* ``Identifier`` is the human readable provider identifier, such as a
  FQDN.

* ``IdentityKey`` is the provider's EdDSA signing key, in either
  Base16 OR Base64 format.


Katzenpost Mix Infrastructure
=============================

Overview
--------

A Katzenpost Provider is strictly a superset of the Katzenpost mix.
Both of these components are provided for by the ``server`` binary.
Each Provider and Mix MUST be white-listed by the Directory Authority (PKI)
in order to participate in the network.

Building the ``server`` binary
------------------------------

The easiest way to build the nonvoting Authority server is with
this single commandline::

   go get github.com/katzenpost/daemons/server

However you can of course use git to clone all of our git
repositories and dependencies. You may then build the
nonvoing authority as follows::

   cd $GOPATH/github.com/katzenpost/daemons/server
   go build

Neither of these build strategies is ideal because the latest
versions of any of our software dependencies may make breaking
changes. We therefore recommend using our golang vendoring system
to perform the build as described above.


``server`` Commandline Usage
----------------------------

The ``server`` commandline usage is as follows::

  ./server -h
  Usage of ./server:
    -f string
          Path to the server config file. (default "katzenpost.toml")
    -g    Generate the keys and exit immediately.


The command output when generating keys looks like this::

  ./server -f my_katzenpost_mix_server.toml -g
  22:51:55.377 NOTI server: Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.
  22:51:55.377 NOTI server: AEZv5 implementation is hardware accelerated.
  22:51:55.377 NOTI server: Server identifier is: 'example.com'
  22:51:55.379 NOTI server: Server identity public key is: 2628F87F2806048C95F060DA9CD3D8F9BE7550BFB9EE85F213381BC04C047650
  22:51:55.379 NOTI server: Server link public key is: CCDC5C105E649D543DF1CF397A17638F812F95B7E572288F4602F8EC01EC4F3C


Configuring Mixes and Providers
-------------------------------

Katzenpost mixes and providers have identical configuration files
except that the configuration for a provider has a ``Provider`` section
AND the ``Server`` section specifies ``IsProvider = true``.

Server section
``````````````

The Server section contains mandatory information common to all nodes,
for example::

  [Server]
    Identifier = "example.com"
    Addresses = [ "192.0.2.1:29483", "[2001:DB8::1]:29483" ]
    DataDir = "/var/lib/katzenpost"
    IsProvider = true

* ``Identifier`` is the human readable identifier for the node (eg:
  FQDN).

* ``Addresses`` are the IP address/port combinations that the server
  will bind to for incoming connections. IPv4 and/or IPv6 may be
  specified.

* ``DataDir`` is the absolute path to the server's state files.

* ``IsProvider`` specifies if the server is a provider (vs a mix).


PKI section
```````````

The PKI section contains the directory authority configuration
for the given mix or provider, for example::

  [PKI]
    [PKI.Nonvoting]
      Address = "192.0.2.2:2323"
      PublicKey = "kAiVchOBwHVtKJVFJLsdCQ9UyN2SlfhLHYqT8ePBetg="

* ``Nonvoting`` is a simple non-voting PKI for test deployments.

* ``Address`` is the IP address/port combination of the directory authority.

* ``PublicKey`` is the directory authority's public key in Base64 or Base16 format.


Logging section
```````````````

The Logging section controls the logging, for example::

  [Logging]
    Disable = false
    File = "/var/log/katzenpost.log"
    Level = "DEBUG"

* ``Disable`` is used to disable logging if set to ``true``.

* ``File`` specifies the file to log to. If ommited then stdout is used.

* ``Debug`` may be set to one of the following:

* ERROR
* WARNING
* NOTICE
* INFO
* DEBUG

**Warning: The `DEBUG` log level is unsafe for production use.**


Management section
``````````````````

The management section specifies connectivity information for the
Katzenpost control protocol which can be used to make configuration
changes during run-time. An example configuration looks like this::

  [Management]

    Enable = true
    Path = "/var/lib/katzenpost/thwack.sock"

* ``Disable`` is used to disable the management interface if set to
  ``true``.

* ``Path`` specifies the path to the management interface socket. If
  left empty then `management_sock` will be used under the DataDir.


Provider section
````````````````

The Provider secton specifies the Provider configuration.
This section of the configuration has sensible defaults for
every field and can therefore be omitted unless you wish
to deviate from the defaults.

The top-level Provider configuration parameters include:

* ``BinaryRecipients`` if set to ``true`` disables all Provider side
  recipient pre-processing, including removing trailing `NUL` bytes,
  case normalization, and delimiter support.

* ``CaseSensitiveRecipients`` if set to ``true`` disables recipient
  case normalization. If left unset, all user names will be converted
  to lower case.

* ``RecipientDelimiter`` is the set of characters that separates a user name
  from it's extension (eg: `alice+foo`).

* ``AltAddresses`` is the map of extra transports and addresses at which
  the Provider is reachable by clients.  The most useful alternative
  transport is likely ("tcp") (`core/pki.TransportTCP`).


Kaetzchen Configuration
'''''''''''''''''''''''

We will now consider configuring Provider-side autoresponder service
which our specifications and documentation shall refer to as
``Kaetzchen``. Consider the following simple configuration example::

  [Provider]

    [[Provider.Kaetzchen]]
      Capability = "fancy"
      Endpoint = "+fancy"
      Disable = false

      [Provider.Kaetzchen.Config]
        rpcUser = "username"
        rpcPass = "password"
        rpcUrl = "http://127.0.0.1:11323/"

    [[Provider.Kaetzchen]]
      Capability = "shiny"
      Endpoint = "+shiny"
      Disable = false

The ``Kaetzchen`` field is the list of configured Kaetzchen
(auto-responder agents) for this provider. In the above example we
configured two Kaetzchen, one called ``fancy`` and the other
``shiny``. As you can see, ``fancy`` has some configuration parameters
that ``shiny`` does not.

Lets review the Kaetzchen configuration parameters:

* ``Capability`` is the capability exposed by the agent.

* ``Endpoint`` is the provider side endpoint that the agent will accept
  requests at. While not required by the spec, this server only
  supports Endpoints that are lower-case local-parts of an e-mail
  address. By convention these endpoint strings begin with ``+``.

* ``Config`` is the extra per agent arguments to be passed to the agent's
  initialization routine.

* ``Disable`` disabled a configured agent.


Next we will discuss database backends for supporting various Provider services.

* ``UserDB`` is the userdb backend configuration.

* ``SpoolDB`` is the user message spool configuration.

* ``SQLDB`` is the SQL database backend configuration.


Provider User Database Configuration
''''''''''''''''''''''''''''''''''''

``UserDB`` is the user database configuration.  If left empty the simple
BoltDB backed user database will be used with the default database. A simple
configuration example::

  [Provider.UserDB]
    Backend = "bolt"

    [Provider.UserDB.Bolt]
      UserDB = "my_users.db"


* ``Backend`` is the active userdb backend. If left empty, the BoltUserDB
  backend will be used (`bolt`).

If the ``bolt`` backend is specified there is one configuration parameter
available under this section:

* ``UserDB`` is the path to the user database. If left empty it will use
  `users.db` under the DataDir.


Next we will examine a configuration example which demonstrates using
a user database via HTTP::

    [Provider.UserDB]
      [Provider.UserDB.ExternUserDB]
        ProviderURL = "http://localhost:8080/"

* ``ExternUserDB`` is the external http user authentication mechanism.

* ``ProviderURL`` is the base url used for the external provider authentication API.


Provider Spool Database Configuration
'''''''''''''''''''''''''''''''''''''

The Provider spool database stores received messages for later
retreival by clients. A simple configuration example follows::

  [Provider.SpoolDB]
    Backend = "bolt"

    [Provider.SpoolDB.Bolt]
      SpoolDB = "my_spool.db"

* ``SpoolDB`` is the path to the user message spool. If left empty, it
  will default to `spool.db` under the DataDir.


Using the Postgres SQL Database Backend
'''''''''''''''''''''''''''''''''''''''

Lastly, we will explore how to use a SQL database as the backend for the
user and spool databases, for example::

  [Provider]
    [Provider.SQLDB]
      Backend = "pgx"
      DataSourceName = "postgresql://provider:s3cr3tp0stgr355@127.0.0.1:5433/katzenpost"
    [Provider.SpoolDB]
      Backend = "sql"
    [Provider.UserDB]
      Backend = "sql"

This configuration sample demonstrates how to use a Postgres database
for both the user database and the spool databse. The ``Backend`` parameter
is set to ``pgx`` which means "use a postgresql database".

* ``DataSourceName`` is the SQL data source name or URI. The format
  of this parameter is dependent on the database driver being used.


Setup the Postgres SQL database backend:

0. Install postgres
   Postgres 9.5 or later is required. On a debian
   system you can install it like so::

     apt install postgresql

1. Configure postgres access
   The pg_hba.conf file is the place to configure access to the
   databases. It's parsed from top to bottom, first matching rule is
   applied. You probably need to add a rule for your 'provider' user
   fairly early. On a debian system this file may be located here::

     /etc/postgresql/9.6/main/pg_hba.conf

   Start a shell as the postgres user. If you are superuser
   you can use su or sudo to start the shell as postgres like::

     sudo -u postgres

   or without sudo::

     su - postgres

   Add the database user "provider"::

     createuser -U postgres provider

   Add a database::

     createdb -U postgres -O provider katzenpost

   Start the postgres shell::

     psql

   Set the password for your new user::

     ALTER USER provider WITH PASSWORD 's3cr3tp0stgr355';

   Test to see if you can connect::

     psql -U provider -h 127.0.0.1 katzenpost

   If all goes fine, it's time to load the SQL, that creates the
   Katzenpost database schema and stored procedures::

     psql -U provider --password -d katzenpost -h 127.0.0.1 -f create_database-postgresql.sql

   That sql script is located in our ``server`` git repository, here:
   https://github.com/katzenpost/server/blob/master/internal/sqldb/create_database-postgresql.sql

3. Start the Katzenpost server.


Runtime configuration changes with the management socket
--------------------------------------------------------

The ``socat`` commandline utility can be use to connect to the management socket
and issue commands. Connect with a commandline like so::

   socat unix:/<path-to-data-dir>/management_sock STDOUT


The following commands are possible:

* ``ADD_USER`` - Add a user and associate it with the given link key in either hex or base64.
  The syntax of the command is as follows::

    ADD_USER alice X25519_public_key_in_hex_or_base64

* ``UPDATE_USER`` - Update the link key of a given user.
  The syntax of the command is as follows::

    UPDATE_USER alice X25519_public_key_in_hex_or_base64

* ``REMOVE_USER`` - Remove a given user.
  The syntax of the command is as follows::

    REMOVE_USER alice

* ``SET_USER_IDENTITY`` - Set a given user's identity key.
  The syntax of the command is as follows::

    SET_USER_IDENTITY alice ED25519_public_key_in_hex_or_base64

* ``USER_IDENTITY`` - Retrieve the identity key of the given user.
  The syntax of the command is as follows::

    USER_IDENTITY alice


Mailproxy Client Daemon
=======================

Overview
--------

Mailproxy is one of many possible clients for using a Katzenpost mix
network. It supports POP3 and SMTP for message retreival and message
transmission respectively and is intended to run on a user's localhost
to allow standard mail clients to send and receive mail over the
mixnet.

Mailproxy is a daemon which runs in the background and periodically
transmits and receives messages. Once it receives a message it will be
queued locally and encrypted onto disk for later retreival via POP3.


Configuration
-------------

The Proxy Section
`````````````````

The Proxy section contains mandatory proxy configuration, for example::

  [Proxy]
    POP3Address = "127.0.0.1:2524"
    SMTPAddress = "127.0.0.1:2525"
    DataDir = "/home/user/.local/share/katzenpost"


* `POP3Address` is the IP address/port combination that the mail proxy
  will bind to for POP3 access. If omitted `127.0.0.1:2524` will be
  used.

* `SMTPAddress` is the IP address/port combination that the mail proxy
  will bind to for SMTP access. If omitted `127.0.0.1:2525` will be
  used.

* `DataDir` is the absolute path to mailproxy's state files.


The Logging Section
```````````````````

The Logging section controls the logging, for example::

  [Logging]
    Disable = false
    File = "/home/user/.local/share/katzenpost/katzenpost.log"
    Level = "DEBUG"

* `Disable` disables logging entirely if set to `true`.

* `File` specifies the log file, if omitted stdout will be used.

* `Level` specifies the log level out of `ERROR`, `WARNING`, `NOTICE`,
  `INFO` and `DEBUG`.

**Warning: The `DEBUG` log level is unsafe for production use.**


The NonvotingAuthority Section
``````````````````````````````

The NonvotingAuthority section specifies one or more nonvoting
directory authorities, for example::

  [NonvotingAuthority]
    [NonvotingAuthority.TestAuthority]
      Address = "192.0.2.2:2323"
      PublicKey = "kAiVchOBwHVtKJVFJLsdCQ9UyN2SlfhLHYqT8ePBetg="

This configuration section supports multiple entries. In the above
example, the entry is labelled as `TestAuthority` and is referred
to later in the `Account` section of the mailproxy configuration.

* `Address` is the IP address/port combination of the directory
  authority.

* `PublicKey` is the directory authority's public key in Base64 or
  Base16 format.


The Account Section
```````````````````

The Account section specifies account configuration(s), for example::

  [[Account]]
    User = "alice"
    Provider = "example.com"
    ProviderKeyPin = "0AV1syaCdBbm3CLmgXLj6HdlMNiTeeIxoDc8Lgk41e0="
    Authority = "TestAuthority"


* ``User`` is the account user name.

* ``Provider`` is the provider identifier used by this account.

* ``ProviderKeyPin`` is the optinal pinned provider signing key in
  Base64 or Base16 format.

* ``Authority`` is the authority configuration used by this account.


The Management section
``````````````````````

The Management section specifies the management interface configuration,
for example::

  [Management]
    Enable = true
    Path = "/home/user/.local/share/katzenpost/management_sock"

* ``Enable`` enables the management interface.

* ``Path`` specifies the path to the management interface socket.  If
  left empty it will use `management_sock` under the DataDir.


Using the mangement interface
-----------------------------

Several mailproxy management commands are supported:

* ``GET_RECIPIENT`` - Returns the given user's public identity key.
  The syntax of the command is as follows::

    GET_RECIPIENT username

* ``SET_RECIPIENT`` - Sets the given user's public identity key specified in hex or base64.
  The syntax of the command is as follows::

    SET_RECIPIENT username X25519_public_key_in_hex_or_base64

* ``REMOVE_RECIPIENT`` - Removes a given recipient.
  The syntax of the command is as follows::

    REMOVE_RECIPIENT username

* ``LIST_RECIPIENTS`` - Lists all the recipients.
  This command expects no arguments.
