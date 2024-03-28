// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

/*
Client2 is the new low level client for Katzenpost mix networks.

# Introduction

**Please see the ThinClient section of this documentation** to learn about
Katzenpost client integration. The vast majority of applications will use
the ThinClient type and not any other part of this library.

Client2 uses a privilege separated design where many applications use a
thin client library to connect to the client2 daemon which multiplexes
their connections to the mixnet entry node.

A Katzenpost mixnet client has several responsibilities at minimum:

* compose Sphinx packets
* decrypt SURB replies
* send and receive Noise protocol messages
* keep up to date with the latest PKI document

# Overview

Client2 is essentially a long running daemon process that listens on an abstract unix domain
socket for incoming thin client library connections. Many client applications can use the
same client2 daemon. Those connections are multiplexed into the daemon's single
connection to the mix network.

Therefore applications will be integrated with Katzenpost using the thin client library
which gives them the capability to talk with the client2 daemon and in that way interact
with the mix network. The reason we call it a thin client library is because it does not
do any mixnet related cryptography since that is already handled by the client2 daemon.
In particular, the PKI document is stripped by the daemon before it's passed on to the
thin clients. Likewise, thin clients don't decrypt SURB replies or compose Sphinx packets,
instead all the that Noise, Sphinx and PKI related cryptography is handled by the daemon.

# Thin client and daemon protocol

Note that the thin client daemon protocol listens on an abstract unix domain
of type `SOCK_SEQPACKET` which is defined as:

	**SOCK_SEQPACKET** (since Linux 2.6.4), is a connection-oriented socket that preserves message
	boundaries and delivers messages in the order that they were sent.

In golang this is referred to by the "unixpacket" network string.

## Client socket naming convention

Thin clients MUST randomize their abstract unix domain socket name otherwise the static
name will prevent multiplexing because the kernel requires that the connection be between
uniquely nameed socket pairs. The Katzenpost reference implementation of the thin client library
selects a socket name with four random hex digits appended to the end of the name
like so:

	@katzenpost_golang_thin_client_DEADBEEF

## Daemon socket naming convention

The client2 daemon listens on an abstract unix domain socket with the following name:

	@katzenpost

## Protocol description

Upon connecting to the daemon socket the client must wait for two
messages. The first message received must contain a connection status
and the second message must contain a new PKI document event. This marks
the end of the initial connection sequence. Note that this PKI document
is stripped of all cryptographic signatures.

In the next protocol phase, the client may send `Request` messages to the daemon
in order to cause the daemon to encapsulate the given payload in a Sphinx packet
and send it to the entry node. Likewise the daemon my send the client `Response`
messages at any time during this protocol phase. These `Response` messages may
indicated a connection status change, a new PKI document or a message sent or reply event.
*/
package client2
