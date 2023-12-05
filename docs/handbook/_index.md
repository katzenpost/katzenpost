---
title: "Administrators Guide"
linkTitle: "Administrators Guide"
description: ""
categories: [""]
tags: [""]
weight: "30"
author: ["David Stainton"]
version: 0
---

**Abstract**

Thank you for interest in Katzenpost! This document describes how to use
and configure the Katzenpost Mix Network software system. The target
audience for this document is systems administrators. This document
assumes you are familiar with using unix systems, git revision control
system and building golang binaries.

## Introduction

Katzenpost can be used as a message oriented transport for a variety of
applications and is in no way limited to the e-mail use case
demonstrated by the `mailproxy` client/library. Other possible
applications of Katzenpost include but are not limited to: instant
messenger applications, crypto currency transaction transport, bulletin
board systems, file sharing and so forth.

The Katzenpost system has four component categories:

- public key infrastructure
- mixes
- Providers
- clients

Providers has a superset of mixes that fulfill two roles: 1. The initial
hop in the route and therefore as an ingress hop this node authenticates
clients and does per client rate limiting. 2. The terminal hop in the
route and therefore can either store and forward or proxy to a
`Kaetzchen` aka a mixnet service.

This handbook will describe how to use and deploy each of these. The
build instructions in this handbook assume that you have a proper golang
environment with at least golang 1.10 or later AND the git revision
control system commandline installed.

### Building the latest stable version of Katzenpost

NOTE: Find out what our latest stable version tag by looking at the
`releases.md` file in the top-level of this repository.

1. Make sure you have a recent version of Go that supports go modules.
2. Follow the build instructions for each Katzenpost component you want to build.

There are two server infrastructure components:

- https://github.com/katzenpost/katzenpost/server
- https://github.com/katzenpost/katzenpost/authority

There are several clients. Our latest work-in-progress:

- https://github.com/katzenpost/catchat

The old client from the Panoramix EU 2020 grant deliverable:

- https://github.com/katzenpost/mailproxy

Additionally HashCloak makes crypto currency clients that work with Katzenpost:

- https://github.com/hashcloak

### The Katzenpost Configuration File Format

Each Katzenpost component has a configuration file in the TOML format.
This handbook will give you all the details you need to know to
configure each of these configuration files. To learn more about the
TOML format see: https://github.com/toml-lang/toml#toml

NOTE: `#` may be used at the beginning of a line to denote a comment
instead of an effective configuration line.

### Notes on Building a Test Mix Network

See our docker repo:

- https://github.com/katzenpost/katzenpost/docker

