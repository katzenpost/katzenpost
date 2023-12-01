---
title: "Mailproxy Client Daemon"
linkTitle: "Administrators Guide"
description: ""
categories: [""]
tags: [""]
author: []
version: 0
draft: false
---

## Overview

Mailproxy is one of many possible clients for using a Katzenpost mix
network. It supports POP3 and SMTP for message retreival and message
transmission respectively and is intended to run on a user\'s localhost
to allow standard mail clients to send and receive mail over the mixnet.

Mailproxy is a daemon which runs in the background and periodically
transmits and receives messages. Once it receives a message it will be
queued locally and encrypted onto disk for later retreival via POP3.

Upon receiving the HUP signal, mailproxy will rescan it\'s recipients
directory to check for new recipients. Other signals trigger a clean
shutdown.

## Configuration

## The Proxy Section

The Proxy section contains mandatory proxy configuration, for example:

```
[Proxy]
    POP3Address = "127.0.0.1:2524"
    SMTPAddress = "127.0.0.1:2525"
    DataDir = "/home/user/.local/share/katzenpost
```

- `POP3Address` is the IP address/port combination that the mail proxy will bind to for POP3 access. If omitted `127.0.0.1:2524` will be used.
- `SMTPAddress` is the IP address/port combination that the mail proxy will bind to for SMTP access. If omitted `127.0.0.1:2525` will be used.
- `DataDir` is the absolute path to mailproxy's state files.
- `NoLaunchListeners` is set to true to disable the SMTP and POP3 listeners.

## The Logging Section

The Logging section controls the logging, for example:

```
[Logging]
    Disable = false
    File = "/home/user/.local/share/katzenpost/katzenpost.log"
    Level = "DEBUG"
```

- `Disable` disables logging entirely if set to `true`
- `File` specifies the log file, if omitted stdout will be sed.
- `Level` specifies the log level out of
- ERROR
- WARNING
- NOTICE
- INFO
- DEBUG

**Warning:** The `DEBUG` log level is unsafe for production use.

## The NonvotingAuthority Section

The NonvotingAuthority section specifies one or more nonvoting directory
authorities, for example:

    [NonvotingAuthority]
      [NonvotingAuthority.TestAuthority]
        Address = "192.0.2.2:2323"
        PublicKey = "kAiVchOBwHVtKJVFJLsdCQ9UyN2SlfhLHYqT8ePBetg="

This configuration section supports multiple entries. In the above
example, the entry is labelled as `TestAuthority` and is
referred to later in the `Account` section of the mailproxy
configuration.

- `Address` is the IP address/port combination of the directory authority.
- `PublicKey` is the directory authority's public key is Base64 or Base16 format.

## The Account Section

The Account section specifies account configuration(s), for example:

```
[[Account]]
    User = "alice"
    Provider = "example.com"
    ProviderKeyPin = "0AV1syaCdBbm3CLmgXLj6HdlMNiTeeIxoDc8Lgk41e0="
    Authority = "TestAuthority"
    InsecureKeyDiscovery = true
```

- `User` is the account user name.
- `Provider` is the provider identifier used by this account.
- `ProviderKeyPin` is the optional pinned provider signing key in Base64 or Base16 format.
- `Authority` is the authority configuration used by this account.
- `InsecureKeyDiscovery` is set to true in order to allow unverified user identity key lookups to be used for end-to-end encryption of messages.

## The Management section

The Management section specifies the management interface configuration,
for example:

```
[Management]
    Enable = true
    Path = "/home/user/.local/share/katzenpost/management_sock"
```

- `Enable` enables the management interface.
- `Path` specifies the path to the management interface socket. If left empty it will use [management_sock]{.title-ref} under the DataDir.

Using the management interface

Several `mailproxy` management commands are supported:

- `GET_RECIPIENT` - Returns the given user\'s public identity key. The syntax of the command is as follows:

```
GET_RECIPIENT username
```

- `SET_RECIPIENT` - Sets the given user's public identity key specified in hex or base64. The syntax of the command is as follows:

```
SET_RECIPIENT username X25519_public_key_in_hex_or_base64
```

- `REMOVE_RECIPIENT` - Removes a given recipient. The syntax of the command is as follows:

```
REMOVE_RECIPIENT username
```

- `LIST_RECIPIENTS` - Lists all the recipients. This command expects no arguments.
