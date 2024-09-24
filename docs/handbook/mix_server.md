---
title: "Mix Server Infrastructure"
linkTitle: ""
description: ""
categories: [""]
tags: [""]
author: []
version: 0
draft: false
---

## Overview

A Katzenpost Provider is strictly a superset of the Katzenpost mix. Both
of these components are provided for by the `server` binary. Each
Provider and Mix MUST be white-listed by the Directory Authority (PKI)
in order to participate in the network.

## Install

See the mix server readme:

- https://github.com/katzenpost/katzenpost/server

## Configuration

A sample configuration file can be found in our docker repository, here:

- https://github.com/katzenpost/katzenpost/docker

## Command Line Usage

The `server` command Line usage is as follows:

```
./server -h
Usage of ./server:
    -f string
        Path to the server config file. (default "katzenpost.toml")
        -g    Generate the keys and exit immediately.
```

The command output when generating keys looks like this:

```
./server -f my_katzenpost_mix_server.toml -g
22:51:55.377 NOTI server: Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.
22:51:55.377 NOTI server: AEZv5 implementation is hardware accelerated.
22:51:55.377 NOTI server: Server identifier is: 'example.com'
22:51:55.379 NOTI server: Server identity public key is: 2628F87F2806048C95F060DA9CD3D8F9BE7550BFB9EE85F213381BC04C047650
22:51:55.379 NOTI server: Server link public key is: CCDC5C105E649D543DF1CF397A17638F812F95B7E572288F4602F8EC01EC4F3C
```

Note that if you choose to configure logging to a file one disk, you can
implement log rotation by moving the log file and then sending the `HUP`
to the authority server process. This will cause the daemon to rewrite
the log file in the location specified by the config file.

## Configuring Mixes and Providers

Katzenpost mixes and providers have identical configuration files except
that the configuration for a provider has a `Provider` section AND the
`Server` section specifies `IsProvider = true`.

## Server section

The Server section contains mandatory information common to all nodes,
for example:

```
[Server]
    Identifier = "example.com"
    Addresses = [ "tcp://192.0.2.1:29483", "tcp6://[2001:DB8::1]:29483", "http://192.168.0.2.1:15242", "http://[2001:DB8::1]:24144" ]
    DataDir = "/var/lib/katzenpost"
    IsProvider = true
```

- `Identifier` is the human readable identifier for the node (eg: FQDN).
- `Addresses` are the address URLs that the server will advertise in the PKI and bind to for incoming connections, unless BindAddresses is specifiec.
   TCP listeners are specified by scheme tcp:// and QUIC (UDP) by http://. IPv4 and/or IPv6 may be specified.
- `BindAddresses` are the address URLs describing local listeners that the server will bind to for incoming connections, and not advertise in the PKI.
- `DataDir` is the absolute path to the server\'s state files.
- `IsProvider` specifies if the server is a provider (vs a mix).

## PKI section

The PKI section contains the directory authority configuration for the
given mix or provider, for example:

```
[PKI]
  [PKI.Nonvoting]
    Address = "192.0.2.2:2323"
    PublicKey = "kAiVchOBwHVtKJVFJLsdCQ9UyN2SlfhLHYqT8ePBetg="
```

- `Nonvoting` is a simple non-voting PKI for test deployments.
- `Address` is the IP address/port combination of the directory authority.
- `PublicKey` is the directory authority\'s public key in Base64 or Base16 format.

## Logging section

The Logging section controls the logging, for example:

```
[Logging]
    Disable = false
    File = "/var/log/katzenpost.log"
    Level = "DEBUG"
```

- `Disable` is used to disable logging if set to `true`.
- `File` specifies the file to log to. If omitted then stdout is used.
- `Debug` may be set to one of the following:
- ERROR
- WARNING
- NOTICE
- INFO
- DEBUG

**Warning:** The `DEBUG` log level is unsafe for production use.

## Management section

The management section specifies connectivity information for the
Katzenpost control protocol which can be used to make configuration
changes during run-time. An example configuration looks like this:

```
[Management]
    Enable = true
    Path = "/var/lib/katzenpost/thwack.sock"
```

- `Disable` is used to disable the management interface if set to `true`.
- `Path` specifies the path to the management interface socket. If left empty then [management_sock]{.title-ref} will be used under the DataDir.

## Debug section

Debug is the Katzenpost server debug configuration for advanced tuning.

- `IdentityKey` specifies the identity private key.
- `NumSphinxWorkers` specifies the number of worker instances to use for inbound Sphinx packet processing.
- `NumProviderWorkers` specifies the number of worker instances to use for provider specific packet processing.
- `NumKaetzchenWorkers` specifies the number of worker instances to use for Kaetzchen specific packet processing.
- `SchedulerExternalMemoryQueue` will enable the experimental external memory queue that is backed by disk.
- `SchedulerQueueSize` is the maximum allowed scheduler queue size before random entries will start getting dropped. A value `<= 0` is treated as unlimited.
- `SchedulerMaxBurst` is the maximum number of packets that will be dispatched per scheduler wakeup event.
- `UnwrapDelay` is the maximum allowed unwrap delay due to queueing in milliseconds.
- `ProviderDelay` is the maximum allowed provider delay due to queueing in milliseconds.
- `KaetzchenDelay` is the maximum allowed kaetzchen delay due to queueing in milliseconds.
- `SchedulerSlack` is the maximum allowed scheduler slack due to queueing and or processing in milliseconds.
- `SendSlack` is the maximum allowed send queue slack due to queueing and or congestion in milliseconds.
- `DecoySlack` is the maximum allowed decoy sweep slack due to various external delays such as latency before a loop decoy packet will be considered lost.
- `ConnectTimeout` specifies the maximum time a connection can take to establish a TCP/IP connection in milliseconds.
- `HandshakeTimeout` specifies the maximum time a connection can take for a link protocol handshake in milliseconds.
- `ReauthInterval` specifies the interval at which a connection will be reauthenticated in milliseconds.
- `SendDecoyTraffic` enables sending decoy traffic. This is still experimental and untuned and thus is disabled by default. WARNING: This option will go away once decoy traffic is more concrete.
- `DisableRateLimit` disables the per-client rate limiter. This option should only be used for testing.
- `GenerateOnly` halts and cleans up the server right after long term key generation.

## Provider section

The Provider section specifies the Provider configuration. This section
of the configuration has sensible defaults for every field and can
therefore be omitted unless you wish to deviate from the defaults.

The top-level Provider configuration parameters include:

- `AltAddresses` is the map of extra transports and addresses at which the Provider is reachable by clients. The most useful alternative transport is likely `tcp` in `core/pki.TransportTCP`
- `EnableEphemeralClients` if set to `true` allows ephemeral clients to be created when the Provider first receives a given user identity string.
- `TrustOnFirstUse` if set to `true` the Provider will trust client's wire protocol keys on first use.

### Kaetzchen Configuration

`Kaetzchen` are a simple kind of Provider-side service which receives a
request and replies with a response message. We here discuss built-in
internal kaetzchen services. (see next section for external kaetzchen
plugin system)

Consider the following simple configuration example where we configure
the echo and keyserver services:

```
[Provider]
    [[Provider.Kaetzchen]]
    Capability = "echo"
    Endpoint = "+echo"
    Disable = false

    [[Provider.Kaetzchen]]
    Capability = "keyserver"
    Endpoint = "+keyserver"
    Disable = false
```

The `Kaetzchen` field is the list of configured Kaetzchen
(auto-responder agents) for this provider. In the above example we
configured two Kaetzchen, keyserver and echo which are required by the
mailproxy client.

Lets review the Kaetzchen configuration parameters:

- `Capability` is the capability exposed by the agent.
- `Endpoint` is the provider side endpoint that the agent will accept requests at. While not required by the spec, this server only supports Endpoints that are lower-case local-parts of an e-mail address. By convention these endpoint strings begin with `+`.
- `Config` is the extra per agent arguments to be passed to the agent's initialization routine.
- `Disable` disabled a configured agent.

### External Kaetzchen Plugin Configuration

Currently the Katzenpost server external kaetzchen plugin system uses CBOR
serialised structs over UNIX domain socket to communicate with plugin programs.
That is to say, the katzenpost server will spin up each plugin program one or
more times as specified by it's `MaxConcurrency` parameter, and dial (connect)
to the UNIX domain socket specified in the first line of standard output
written by the client plugin.

Thereafter, requests that arrive for the specific plugin program, as identified
by the "Endpoint" configuration parameter, are written to this UNIX socket by
the mix server as CBOR encoded structs, specified in
server/cborplugin/client.go:

```
// Request is the struct type used in service query requests to plugins.
type Request struct {
	ID      uint64
	Payload []byte
	HasSURB bool
}
```

Responses are written synchronously (the mix server will wait for a Response
before sending another Request to the plugin) to the mix server via the UNIX
domain socket similarly, writing a CBOR encoded struct, specified in
server/cborplugin/client.go:

```
// Response is the response received after sending a Request to the plugin.
type Response struct {
	Payload []byte
}
```

Response Payloads must fit inside the Katzenpost mix packet size as defined by
the operators of the network used. There is not a facility for informing the
plugin of the payload size or informing it whether the response was accepted.


Here's a configuration example for the external currency service:

```
[[Provider.CBORPluginKaetzchen]]
  Capability = "zec"
  Endpoint = "+zec"
  Disable = false
  Command = "/home/user/test_mixnet/bin/currency"
  MaxConcurrency = 10
[Provider.PluginKaetzchen.Config]
  log_dir = "/home/user/test_mixnet/zec_tx_logs"
  f = "/home/user/test_mixnet/currency_zec/curreny.toml"
```

We've written echo services in golang and rust as an example here:

- https://github.com/katzenpost/katzenpost/server_plugins

### Provider User Database Configuration

`UserDB` is the user database configuration. If left empty the simple
BoltDB backed user database will be used with the default database. A
simple configuration example:

```
[Provider.UserDB]
    Backend = "bolt"

    [Provider.UserDB.Bolt]
    UserDB = "my_users.db"
```

-   `Backend` is the active userdb backend. If left empty, the BoltUserDB backend will be used `bolt`

If the `bolt` backend is specified there is one configuration parameter
available under this section:

- `UserDB` is the path to the user database. If left empty it will use `users.db` under the DataDir.

Next we will examine a configuration example which demonstrates using a
user database via HTTP:

```
[Provider.UserDB]
  [Provider.UserDB.ExternUserDB]
    ProviderURL = "http://localhost:8080/"
```

- `ExternUserDB` is the external http user authentication mechanism.
- `ProviderURL` is the base url used for the external provider authentication API.

### Provider Spool Database Configuration

The Provider spool database stores received messages for later retreival
by clients. A simple configuration example follows:

```
[Provider.SpoolDB]
    Backend = "bolt"

[Provider.SpoolDB.Bolt]
    SpoolDB = "my_spool.db"
```

- `SpoolDB` is the path to the user message spool. If left empty, it will default to `spool.db` under the DataDir.

### Using the Postgres SQL Database Backend

Lastly, we will explore how to use a SQL database as the backend for the
user and spool databases, for example:

```
[Provider]
  [Provider.SQLDB]
    Backend = "pgx"
    DataSourceName = "postgresql://provider:s3cr3tp0stgr355@127.0.0.1:5433/katzenpost"
  [Provider.SpoolDB]
    Backend = "sql"
  [Provider.UserDB]
    Backend = "sql"
```

This configuration sample demonstrates how to use a Postgres database
for both the user database and the spool database. The `Backend`
parameter is set to `pgx` which means "use a postgresql database".

- `DataSourceName` is the SQL data source name or URI. The format of this parameter is dependent on the database driver being used.

### Setup the Postgres SQL database backend:

Install postgres Postgres 9.5 or later is required. On a debian system you can install it like so:

```
apt install postgresql
```

Configure postgres access The `pg_hba.conf` file is the place to
configure access to the databases. It's parsed from top to bottom,
first matching rule is applied. You probably need to add a rule for
your `provider` user fairly early. On a debian system this file
may be located here:

```
/etc/postgresql/9.6/main/pg_hba.conf
```

Start a shell as the postgres user. If you are superuser you can use
`su` or `sudo` to start the shell as postgres like:

```
sudo -u postgres
```

or without sudo:

```
su - postgres
```

Add the database user `provider`:

```
createuser -U postgres provider
```

Add a database:

```
createdb -U postgres -O provider katzenpost
```

Start the postgres shell:

psql

Set the password for your new user:

```
ALTER USER provider WITH PASSWORD 's3cr3tp0stgr355';
```

Test to see if you can connect:

```
psql -U provider -h 127.0.0.1 katzenpost
```

If all goes fine, it's time to load the SQL, that creates the
Katzenpost database schema and stored procedures:

```
psql -U provider --password -d katzenpost -h 127.0.0.1 -f create_database-postgresql.sql
```

That SQL script is located in our `server` git repository, here:

- https://github.com/katzenpost/katzenpost/blob/master/server/internal/sqldb/create_database-postgresql.sql

2.  Start the Katzenpost server.

## Runtime configuration changes with the management socket

The `socat` commandline utility can be use to connect to the management
socket and issue commands. Connect with a commandline like so:

```
socat unix:/<path-to-data-dir>/management_sock STDOUT
```

The following commands are possible:

- `QUIT` - Exit this management socket session.
- `SHUTDOWN` - Cause the server to gracefully shutdown.
- `ADD_USER` - Add a user and associate it with the given link key in either hex or base64. The syntax of the command is as follows:

```
ADD_USER alice X25519_public_key_in_hex_or_base64
```

- `UPDATE_USER` - Update the link key of a given user. The syntax of the command is as follows:

```
UPDATE_USER alice X25519_public_key_in_hex_or_base64
```

- `REMOVE_USER` - Remove a given user. The syntax of the command is as follows:

```
REMOVE_USER alice
```

- `SET_USER_IDENTITY` - Set a given user's identity key. The syntax of the command is as follows:

```
SET_USER_IDENTITY alice X25519_public_key_in_hex_or_base64
```

- `REMOVE_USER_IDENTITY` - Remove a given user's identity key. MUST be called before removing the user with the `REMOVE_USER` command. The syntax of this command is as follows:

```
REMOVE_USER_IDENTITY alice
```

- `USER_IDENTITY` - Retrieve the identity key of the given user. The syntax of the command is as follows:

```
USER_IDENTITY alice
```

- `SEND_RATE` - Sets the rate limiter to the given packets per minute rate:

```
SEND_RATE 30
```

- `SEND_BURST` - Sets the rate limiter burst to the given maximum:

```
SEND_BURST 4
```

- `START_KAETZCHEN` - Start the Kaetzchen identified by capability:

```
START_KAETZCHEN echo
```

- `STOP_KAETZCHEN` - Stop the Kaetzchen identified by capability:

```
STOP_KAETZCHEN echo
```
