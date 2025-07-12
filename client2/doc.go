// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

/*
Client2 is the new low level client for Katzenpost mix networks.

# Introduction

Client2 uses a privilege separated design where many applications use a
thin client library to connect to a single client2 daemon which multiplexes
their connections to the mixnet Gateway node.

A Katzenpost mixnet client has several responsibilities at minimum:

* compose Sphinx packets
* decrypt SURB replies
* send and receive PQ Noise protocol messages
* keep up to date with the latest PKI document

# Overview

Applications will be integrated with Katzenpost using the thin client library
which gives them the capability to talk with the client2 daemon and in that way interact
with the mix network. The reason we call it a thin client library is because it does not
do any mixnet related cryptography since that is already handled by the client2 daemon.
In particular, the PKI document is stripped by the daemon before it's passed on to the
thin clients. Likewise, thin clients don't decrypt SURB replies or compose Sphinx packets,
instead all the that PQ Noise, Sphinx and PKI related cryptography is handled by the daemon.

For more details, please see our Thin client design document:
https://katzenpost.network/docs/specs/thin_client.html
*/
package client2
