---
title: "Public Key Infrastructure"
linkTitle: ""
description: ""
categories: [""]
tags: [""]
author: []
version: 0
draft: false
---

## Overview

This is essentially a single point of failure. If this PKI system
becomes compromised by an adversary it\'s game over for anonymity and
security guarantees. Consider using the voting authority instead.

The Katzenpost voting Directory Authority system is a replacement for
the non-voting Directory Authority. However it's voting protocol is
NOT byzantine fault tolerant. Therefore a Directory Authority server
which is participating in the voting protocol can easily perform a
denial of service attack for each voting round. This would cause the mix
network to become totally unusable.

All Katzenpost PKI systems have two essential components:

- A client library
- Server infrastructure

Furthermore this client library has two types of users, namely mixes and
clients. That is, mixes must use the library to upload/download their
mix descriptors and clients use the library to download a network
consensus document so that they can route messages through the mix
network.

## Install

See the authority readme:

- https://github.com/katzenpost/katzenpost/authority

## Configuration

A sample configuration file can be found in our docker repository, here:

- https://github.com/katzenpost/katzenpost/docker

## CLI usage of The Non-voting Directory Authority

The non-voting authority has the following command line usage:

```
./nonvoting --help
Usage of ./nonvoting:
    -f string
        Path to the authority config file. (default "katzenpost-authority.toml")
    -g    Generate the keys and exit immediately.
```

The `-g` option is used to generate the public and private keys for the
Directory Authority. Clients of the PKI will use this public key to
verify retrieved network consensus documents. However before invoking
the authority with this command line option you MUST provide a valid
configuration file. This file will specify a data directory where these
keys will be written. Normal invocation will omit this `-g` option
because the keypair should already be present.

A minimal configuration suitable for using with this `-g` option for
generating the key pair looks like this:

```
[Authority]
    Addresses = [ "192.0.2.1:12345" ]
    DataDir = "/var/run/katzauth"
```

Example invocation command line:

```
./nonvoting -g -f my_authority_config.toml
```

However the invocation may fail if the permissions on the data directory
are not restricted to the owning user:

```
./nonvoting -g -f my_authority_config.toml
Failed to spawn authority instance: authority: DataDir '/var/run/katzauth' has invalid permissions 'drwxr-xr-x'
```
Fix permissions like so:

```
chmod 700 /var/run/katzauth
```
A successful run will print output that looks like this:

```
14:47:43.141 NOTI authority: Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.
14:47:43.142 NOTI authority: Authority identity public key is: 375F00F6EA20ACFB3F4CDCA7FDB50AE427BF02035B6A2F5789281DAA7290B2BB
```

Note that if you choose to configure logging to a file one disk, you can
implement log rotation by moving the log file and then sending the `HUP`
to the authority server process. This will cause the daemon to rewrite
the log file in the location specified by the config file.

## Configuring The Non-voting Directory Authority

### Authority section

The Authority section contains information which is mandatory, for
example:

```
[Authority]
    Addresses = [ "192.0.2.1:29483", "[2001:DB8::1]:29483" ]
    DataDir = "/var/lib/katzenpost-authority"
```

- `Addresses` contains one or more IP addresses which correspond to local network interfaces to listen for connections on. These can be specified as IPv4 or IPv6 addresses.
- `DataDir` specifies the absolute path to the server's state files including the keypair use to sign network consensus documents.

### Logging section

The logging section controls the logging, for example:

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

### Parameters section

The Parameters section holds the network parameters, for example:

```
[Parameters]
    SendRatePerMinute = 30
    Mu = 0.00025
    MuMaxDelay = 9000
    LambdaP = 15.0
    SendShift = 3
    LambdaPMaxDelay = 3000
    LambdaL = 0.00025
    LambdaLMaxDelay = 9000
    LambdaD = 0.00025
    LambdaDMaxDelay = 9000
    LambdaM = 0.00025
    LambdaMMaxDelay = 9000
```  

- `SendRatePerMinute` is the rate limiter maximum allowed rate of packets per client.
- `Mu` is the inverse of the mean of the exponential distribution that the Sphinx packet per-hop mixing delay will be sampled from.
- `MuMaxDelay` is the maximum Sphinx packet per-hop mixing delay in milliseconds.
- `LambdaP` LambdaP is the inverse of the mean of the exponential distribution that **clients** will sample to determine the time interval between sending messages from it\'s FIFO egress queue or drop decoy messages if the queue is empty.
- `LambdaPMaxDelay` is the maximum send interval for LambdaP in milliseconds
- `LambdaL` LambdaL is the inverse of the mean of the exponential distribution that **clients** will sample to determine the time interval between sending decoy loop messages.
- `LambdaLMaxDelay` sets the maximum send interval for LambdaL in milliseconds.
- `LambdaD` is the inverse of the mean of the exponential distribution that **clients** will sample to determine the time interval between sending decoy drop messages.
- `LambdaDMaxDelay` is the maximum send interval in milliseconds.
- `LambdaM` is the inverse of the mean of the exponential distribution that **mixes** will sample to determine send timing of mix loop decoy traffic.
- `LambdaMMaxDelay` sets the maximum delay for LambdaM

### Mixes section

The Mixes array defines the list of white-listed non-provider nodes, for
example:

```
[[Mixes]]
IdentityKey = "kAiVchOBwHVtKJVFJLsdCQ9UyN2SlfhLHYqT8ePBetg="

[[Mixes]]
IdentityKey = "900895721381C0756D28954524BB1D090F54C8DD9295F84B1D8A93F1E3C17AD8"
```

- `IdentityKey` is the node's EdDSA signing key, in either Base16 or Base64 format.

### Provider section

The Providers array defines the list of white-listed Provider nodes, for
example:

```
[[Providers]]
Identifier = "provider1"
IdentityKey = "0AV1syaCdBbm3CLmgXLj6HdlMNiTeeIxoDc8Lgk41e0="

[[Providers]]
Identifier = "provider2"
IdentityKey = "375F00F6EA20ACFB3F4CDCA7FDB50AE427BF02035B6A2F5789281DAA7290B2BB"
```

- `Identifier` is the human readable provider identifier, such as a FQDN.
- `IdentityKey` is the provider's EdDSA signing key, in either Base16 or Base64 format.
