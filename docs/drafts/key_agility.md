---
title: "Key Agility Specification"
description: ""
categories: [""]
tags: [""]
author: ["David Stainton"]
version: 0
draft: true
---

**Abstract**

## 1. Introduction

Mixes and Directory Authority servers MUST be able to rotate or revoke
various cryptographic keys including:

- link key
- signing key
- master key

### 1.1 Conventions Used in This Document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
[RFC2119].

### 1.2. Terminology

# 2. Overview

We use the [KATZCERT](#KATZCERT){.citation} certificate format for
signing the key agility document which encodes a key revocation or
rotation action.

### 2.1 Mix Key Agility

Mixes revoke and rotate keys by including one or more certificates
embedded inside their mix descriptors. Each certificate encodes a revoke
or rotate action for each of the cryptographic keys that a mix uses
which are:

- link layer key
- signing key
- master key

### 2.2 Voting PKI Key Agility

Directory Authority servers [KATZMIXPKI](#KATZMIXPKI){.citation} use
our wire protocol for sending their revocation and rotation certificates
to their peers:

``` 
enum {
      /* Extending the wire protocol Commands. */
      cert(22),
      cert_status(23),
}
```

The structures of these commands are defined as follows:

``` 
struct {
   opaque signing_cert[];
   opaque master_cert[];
} Cert;

struct {
   uint8 error_code;
} CertStatus;
```

### 2.2.1 The Cert Command

The Cert command allows Authority servers to transmit master or signing
key certificates for revocation or rotation.

### 2.2.2 The CertStatus Command

The CertStatus command is sent in response to a Cert command and uses
the following error codes:

``` 
enum {
   descriptor_ok(0),
   descriptor_invalid_signing(1),
   descriptor_invalid_master(2),
   descriptor_failure(3),
} ErrorCodes;
```

## 3. Key Certificate Format

The followoing Key Certificate golang struct is encoded in CBOR
[RFC7049](#RFC7049){.citation} serialization format:

``` 
type KeyCert struct {
   Action string  // Action can be one of: "revoke", "rotate"
   KeyRole string // KeyRole can be one of: "master", "signing" or "link"
   Payload []byte // Can be nil or contain the new key material.
}
```

## Appendix A. References

### Appendix A.1 Normative References

### Appendix A.2 Informative References

[KATZCERT]{#KATZCERT .citation-label}

Stainton, D.,
"Certificate Format Specification",
2018,
https://github.com/katzenpost/katzenpost/blob/master/docs/specs/certificate.md

[KATZMIXPKI]{#KATZMIXPKI .citation-label}

Angel, Y., Piotrowska, A., Stainton, D.,
"Katzenpost Mix Network Public Key Infrastructure Specification",
December 2017,
https://github.com/katzenpost/katzenpost/blob/master/docs/specs/pki.md

[RFC7049]{#RFC7049 .citation-label}

C. Bormannm, P. Hoffman,
"Concise Binary Object Representation (CBOR)",
Internet Engineering Task Force (IETF),
October 2013,
https://tools.ietf.org/html/rfc7049
