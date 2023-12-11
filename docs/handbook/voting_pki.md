---
title: "Voting Directory Authority"
linkTitle: ""
description: ""
categories: [""]
tags: [""]
author: []
version: 0
draft: false
---

# Overview

Most of the mixnet papers are written with the assumption that the
mixnet's PKI exists and performs their functions perfectly. Our mixnet
PKI is a so called Directory Authority design which is inspired by the
Tor's and Mixminion's Directory Authority.

For more details about the design of the Katzenpost voting PKI you
should see our specification document:

- [PKI](https://github.com/katzenpost/katzenpost/blob/master/docs/specs/pki.md)

As with Katzenpost clients and mixes, this authority server uses our
post quantum cryptographic noise based wire protocol as described in the
specification document:

- [Wire Protocol](https://github.com/katzenpost/katzenpost/blob/master/docs/specs/wire-protocol.md)

Each authority's configuration has the public link layer key of each of
it's peers for authenticating the wire protocol connection.

Peers are also configured with each other's public signing key so that
they may verify each other's signatures on votes. The voting system is
used to create a document describing the collective view of the network.
Mixnet clients download the consensus document so that they may utilize
the network to route their Sphinx packets.

# Install

See the authority readme:

- https://github.com/katzenpost/katzenpost/authority

# CLI usage of The Voting Directory Authority

The voting authority has the following command line usage:

```
./voting -h
Usage of ./voting:
    -f string
        Path to the authority config file. (default "katzenpost-authority.toml")
    -g    Generate the keys and exit immediately.
```

The `-g` option is used to generate the public and private signing and
link keys.

# Configuring The Voting Directory Authority

A sample configuration file can be found in our docker repository, here:

- https://github.com/katzenpost/katzenpost/docker

## Authority section

The Authority section contains information which is mandatory, for
example:

```
[Authority]
    Addresses = [ "192.0.2.1:29483", "[2001:DB8::1]:29483" ]
    DataDir = "/var/lib/katzenpost-authority"
```

- `Addresses` contains one or more IP addresses which correspond to local network interfaces to listen for connections on. These can be specified as IPv4 or IPv6 addresses.
- `DataDir` specifies the absolute path to the server\'s state files including the keypair use to sign network consensus documents.

## Logging section

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

## Parameters section

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

## Debug Section

- `IdentityKey` is this authority's EdDSA signing key, in either Base16 OR Base64 format.
- `LinkKey` is this authority's ECDH link layer key, in either Base16 OR Base64 format.
- `Layers` is the number of non-provider layers in the network topology.
- `MinNoderPerLayer` is the minimum number of nodes per layer required to form a valid Document.
- `GenerateOnly` if set to true causes the server to halt and clean up the data dir right after long term key generation.

## Mixes Section

The Mixes configuration section looks like this :

```
[[Mixes]]
    IdentityKey = "kAiVchOBwHVtKJVFJLsdCQ9UyN2SlfhLHYqT8ePBetg="

[[Mixes]]
    IdentityKey = "900895721381C0756D28954524BB1D090F54C8DD9295F84B1D8A93F1E3C17AD8"
```

- `IdentityKey` is the node\'s EdDSA signing key, in either Base16 OR Base64 format.

## Providers Section

Configure like so: :

```
[[Providers]]
    Identifier = "example.com"
    IdentityKey = "0AV1syaCdBbm3CLmgXLj6HdlMNiTeeIxoDc8Lgk41e0="
```

- `Identifier` is the human readable provider identifier, such as a FQDN.
- `IdentityKey` is the provider\'s EdDSA signing key, in either Base16 OR Base64 format.
