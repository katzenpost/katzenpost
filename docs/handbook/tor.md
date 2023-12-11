---
title: "Torification of Katzenpost"
linkTitle: ""
description: ""
categories: [""]
tags: [""]
author: []
version: 0
draft: false
---

**Abstract**

Tor and mixnets provide orthogonal anonymity properties and therefore it
can be advantageous for clients to connect to their mixnet Provider and
Directory Authority service(s) over Tor onion services. This document
describes how to configure these services and a mailproxy client to use
Tor onion services.

# Introduction

This document assumes you have already installed Tor. You can either
install Tor as part of the Tor Browser Bundle or you can install it
standalone. Obviously only clients may be interested in using Tor
Browser Bundle.

1. Install Tor Browser Bundle: https://www.torproject.org/download/download-easy.html.en
2. Install a standlone Tor in Debian/Ubuntu: https://www.torproject.org/docs/debian.html.en

## Mailproxy

Here is a complete mailproxy configuration that uses only Tor onion
services for it\'s communication with the mix network:

```
[Proxy]
    POP3Address = "127.0.0.1:2524"
    SMTPAddress = "127.0.0.1:2525" DataDir = "/home/user/.mailproxy"

[Logging]
    Disable = false Level = "NOTICE"

[NonvotingAuthority]
    [NonvotingAuthority.PlaygroundAuthority]
        Address = "lxqkz5d5e3pehagu.onion:61832"
        PublicKey = "o4w1Nyj/nKNwho5SWfAIfh7SMU8FRx52nMHGgYsMHqQ="

[[Account]]
    User = "alice"
    Provider = "playground"
    ProviderKeyPin = "imigzI26tTRXyYLXujLEPI9QrNYOEgC4DElsFdP9acQ="
    Authority = "PlaygroundAuthority"

[Management]
    Enable = false

[UpstreamProxy]
    PreferedTransports = ["onion"]
    Type = "tor+socks5"
    Network = "tcp" Address = "127.0.0.1:9050"
```
