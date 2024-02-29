---
title: "Uptime Probe"
description: ""
categories: [""]
tags: [""]
author: ["David Stainton"]
version: 1
---

**Abstract**

This document describes the high level architecture and detailed
protocols and behavior required for automatic detection of mix
node uptime statistics for each epoch duration.

## 1. Introduction

We need a way to determine if a given mix node was up the entire epoch or not.
Here our only goal is to determine uptime. Collecting bandwith stats is a separate concern.
This protocol will require the addition of uptime probes to the network which the
dirauth's will add to the PKI document. This additional information in the PKI document
tells each mix node to allow their uptime probe listener to allow connections
from the specified uptime probes.

## 1.1 Changes to the Directory Authority behavior

Each epoch, each dirauth server will select an uptime prober node.
Before the next voting round, dirauths can use their uptime probe states
to determine if a given mix node will remain in the actively used 
network topology layers.

## 1.2 Changes to the mix node behavior

The mix node listens on a new socket that is designated just for the uptime probe service.
This service authenticates with our PQ Noise based wire protocol and only allows
the uptime probes to connect. A simple call and response protocol will work.

## 2. Protocol Description

From the mix node's perspective this is an extremely simple
request/response PQ Noise based protocol.

Two empty request/response commands will do:

```
type UptimeProbeRequest struct{}
type UptimeProbeResponse struct{}
```

The mix node's uptime probe listener expects to receive only `UptimeProbeRequest`
commands and must simply respond with `UptimeProbeResponse`.

## 3. Threat Model

The PQ Noise authentication will be in place such that *only* the current set of
uptime probers will be allowed to connect to the uptime listeners on each mix node.

If an uptime prober lies about the uptime of a mix node this should be overcome if
a majority of uptime probers are honest because each dirauth is going to get it's uptime
statistics from an uptime prober of it's choice. Therefore the dirauths all independently
collect uptime statistics and then vote on whether or not each mix will continue to be
included in the active portion of the mix network.
