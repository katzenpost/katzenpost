---
title: "Katzenpost Client User Guide"
linkTitle: ""
description: ""
categories: [""]
tags: [""]
author: []
version: 0
draft: false
---

## Overview

The Katzenpost client (client2) does NOT directly connect to the dirauths, instead it
is able to download the PKI document from the Gateway. The client's only interaction with the
mixnet is through the Gateway node specified in the client configuration.

Our client is also capable of multiplexing multiple application's interactions with the mixnet.
The client has a "thin client protocol" which allows various thin client libraries to interact
with the client daemon and interact with the mix network.

## Client Configuration

```
// Config is the top level client configuration.
type Config struct {

	// ListenNetwork is the network type that the daemon should listen on for thin client connections.
	ListenNetwork string

	// ListenAddress is the network address that the daemon should listen on for thin client connections.
	ListenAddress string

	// PKISignatureScheme specifies the signature scheme to use with the PKI protocol.
	PKISignatureScheme string

	// WireKEMScheme specifies which KEM to use with our PQ Noise based wire protocol.
	WireKEMScheme string

	// SphinxGeometry
	SphinxGeometry *geo.Geometry

	// Logging
	Logging *Logging

	// UpstreamProxy can be used to setup a SOCKS proxy for use with a VPN or Tor.
	UpstreamProxy *UpstreamProxy

	// Debug is used to set various parameters.
	Debug *Debug

	// CachedDocument is a PKI Document that has a MixDescriptor
	// containg the Addresses and LinkKeys of minclient's Gateway
	// so that it can connect directly without contacting an Authority.
	CachedDocument *cpki.Document

	// PinnedGateways is information about a set of Gateways; the required information that lets clients initially
	// connect and download a cached PKI document.
	PinnedGateways *Gateways

	// VotingAuthority contains the voting authority peer public configuration.
	VotingAuthority *VotingAuthority

	// PreferedTransports is a list of the transports will be used to make
	// outgoing network connections, with the most prefered first.
	PreferedTransports []string
}
```


## Optional SOCKS Proxy

if Type tor+socks5 is used then the User and Password parameters are ignored and
our Tor stream isolation will be used. If Type is socks5 then the User/Password are
passed through to the SOCKS proxy server.

// UpstreamProxy is the outgoing connection proxy configuration.
type UpstreamProxy struct {
	// Type is the proxy type (Eg: "none"," socks5", "tor+socks5").
	Type string

	// Network is the proxy address' network (`unix`, `tcp`).
	Network string

	// Address is the proxy's address.
	Address string

	// User is the optional proxy username.
	User string

	// Password is the optional proxy password.
	Password string
}



