---
title: "Dependencies"
linkTitle: "Dependencies"
description: "A Software Bill of Materials"
weight: 100
categories: [""]
tags: [""]
draft: false
---

**Abstract**

This document describes the Katzenpost software dependencies and their
licenses for the core katzenpost server side components AND the
catshadow anonymous messaging system with QT user interface. This
document is meant to be useful for determining software license
compliance and to assist in audits.

## Dependencies and Licenses

We use [go-modules](https://github.com/golang/go/wiki/Modules) in
each golang git repository to pin dependencies. Therefore these
dependencies can easily be derived from the `go.mod` file at
the root of each git repo. Auditors wishing to quickly learn the
transitive dependencies can do so by looking at these files.

## Core

github.com/katzenpost/katzenpost/core with license AGPL-3.0

The Katzenpost Core library depends on:

- `git.schwanenlied.me/yawning/aez.git` with license `CC0 1.0 Universal`
- `git.schwanenlied.me/yawning/bsaes.git` with [license](https://git.schwanenlied.me/yawning/bsaes/src/master/LICENSE.txt)
- `github.com/agl/ed25519` with license `BSD-3-Clause`
- `github.com/stretchr/testify` with license `MIT`
- `github.com/ugorji/go/codec` with license `MIT`
- `golang.org/x/crypto` with [license](https://github.com/golang/crypto/blob/master/LICENSE)
- `gopkg.in/op/go-logging.v1` with license `BSD-3-Clause`

Forks of external dependencies:

- `github.com/katzenpost/chacha20` with license `AGPL-3.0`
- `github.com/katzenpost/noise` with [license](https://github.com/katzenpost/noise/blob/master/LICENSE)

## Noise

- https://github.com/katzenpost/noise with [license](https://github.com/katzenpost/noise/blob/master/LICENSE)

Noise Protocol Framework: Katzenpost fork of the flynn [noise library](https://github.com/flynn/noise)
Noise depends on:

- `github.com/flynn/noise` with [license](https://github.com/flynn/noise/blob/master/LICENSE)
- `golang.org/x/crypto` with [license](https://github.com/golang/crypto/blob/master/LICENSE)
- `gopkg.in/check.v1` with [license](https://github.com/go-check/check/blob/v1/LICENSE)

Forks of external dependencies:

- `github.com/katzenpost/newhope`

### Newhope

- `github.com/katzenpost/newhope` with license `CC0 1.0 Universal`

Fork of https://git.schwanenlied.me/yawning/newhope

Depends on: `github.com/katzenpost/chacha20` with license AGPL-3.0 and
golang.org/x/crypto with [license](https://github.com/golang/crypto/blob/master/LICENSE)

## Chacha20

https://github.com/katzenpost/chacha20 with license AGPL-3.0 fork of
https://git.schwanenlied.me/yawning/chacha20

depends on:

- github.com/stretchr/testify with license MIT
- golang.org/x/sys with license https://github.com/golang/sys/blob/master/LICENSE

## Authority

github.com/katzenpost/katzenpost/authority with license AGPL-3.0

The Katzenpost Authority depends on:

- github.com/katzenpost/katzenpost/core with license AGPL-3.0
- github.com/BurntSushi/toml with license MIT
- go.etcd.io/bbolt with license MIT
- github.com/stretchr/testify with license MIT
- github.com/ugorji/go/codec with license MIT
- golang.org/x/crypto with license https://github.com/golang/crypto/blob/master/LICENSE
- golang.org/x/net with license https://github.com/golang/net/blob/master/LICENSE
- gopkg.in/op/go-logging.v1 with license BSD-3-Clause

Forks of external dependencies:

- github.com/katzenpost/chacha20 with license AGPL-3.0

## Server

github.com/katzenpost/katzenpost/server with license AGPL-3.0

Server depends on:

- github.com/katzenpost/katzenpost/core with license AGPL-3.0
- github.com/katzenpost/katzenpost/authority with license AGPL-3.0
- git.schwanenlied.me/yawning/aez.git with license CC0 1.0 Universal
- git.schwanenlied.me/yawning/avl.git with license CC0 1.0 Universal
- git.schwanenlied.me/yawning/bloom.git with license CC0 1.0 Universal
- github.com/BurntSushi/toml with license MIT
- go.etcd.io/bbolt with license MIT
- github.com/jackc/pgx with license MIT
- github.com/stretchr/testify with license: MIT
- github.com/ugorji/go/codec with license MIT
- golang.org/x/net with license https://github.com/golang/net/blob/master/LICENSE
- golang.org/x/text with license https://github.com/golang/text/blob/master/LICENSE
- gopkg.in/eapache/channels.v1 with license MIT
- gopkg.in/op/go-logging.v1 with license BSD-3-Clause

## Minclient

github.com/katzenpost/katzenpost/minclient with license AGPL-3.0

Minclient depends on:

- github.com/katzenpost/katzenpost/core with license AGPL-3.0
- github.com/stretchr/testify with license MIT
- gopkg.in/op/go-logging.v1 with license BSD-3-Clause

Forks of external dependencies:

- github.com/katzenpost/noise with license https://github.com/katzenpost/noise/blob/master/LICENSE

## Client

github.com/katzenpost/katzenpost/client with license AGPL-3.0

Client depends on:

- github.com/katzenpost/katzenpost/authority with license AGPL-3.0
- github.com/katzenpost/katzenpost/core with license AGPL-3.0
- github.com/katzenpost/kimchi with license AGPL-3.0
- github.com/katzenpost/katzenpost/minclient with license AGPL-3.0
- github.com/katzenpost/katzenpost/registration_client with license AGPL-3.0
- github.com/BurntSushi/toml with license MIT
- github.com/stretchr/testify with license MIT
- golang.org/x/net with license https://github.com/golang/net/blob/master/LICENSE
- golang.org/x/text with license https://github.com/golang/text/blob/master/LICENSE
- gopkg.in/eapache/channels.v1 with license MIT
- gopkg.in/op/go-logging.v1 with license BSD-3-Clause


## Catshadow

github.com/katzenpost/katzenpost/catshadow with license AGPL-3.0

Client depends on:

- github.com/katzenpost/katzenpost/core with license AGPL-3.0
- github.com/katzenpost/katzenpost/client with license AGPL-3.0
- github.com/katzenpost/kimchi with license AGPL-3.0
- github.com/katzenpost/katzenpost/memspool with license AGPL-3.0
- github.com/katzenpost/katzenpost/panda with license AGPL-3.0
- github.com/katzenpost/doubleratchet with license https://github.com/katzenpost/doubleratchet/blob/master/LICENSE
- github.com/BurntSushi/toml with license MIT
- github.com/stretchr/testify with license MIT
- github.com/ugorji/go/codec with license MIT
- golang.org/x/crypto with license https://github.com/golang/crypto/blob/master/LICENSE
- gopkg.in/eapache/channels.v1 with license MIT
- gopkg.in/op/go-logging.v1 with license BSD-3-Clause

Forks of external dependencies:

- https://github.com/katzenpost/katzenpost/tree/master/panda/crypto with [license](https://github.com/katzenpost/katzenpost/panda/blob/master/crypto/LICENSE)

## Catchat

- https://github.com/katzenpost/catchat with license AGPL-3.0

depends on:

- QT, the C++ library with license LGPL-3.0
- https://doc.qt.io/qt-5/opensourcelicense.html
- github.com/therecipe/qt/core with license LGPL-3.0
- github.com/katzenpost/katzenpost/catshadow with license AGPL-3.0
- github.com/katzenpost/katzenpost/client with license AGPL-3.0
- github.com/dustin/go-humanize with license MIT
- github.com/BurntSushi/toml with license MIT
- github.com/muesli/go-app-paths with license MIT
- golang.org/x/crypto with license https://github.com/golang/crypto/blob/master/LICENSE

## Double Ratchet

github.com/katzenpost/doubleratchet with license https://github.com/katzenpost/doubleratchet/blob/master/LICENSE

fork of double ratchet from @agl's [pond](https://github.com/agl/pond)

depends on:

- github.com/agl/ed25519 with license BSD-3-Clause
- golang.org/x/crypto with license https://github.com/golang/crypto/blob/master/LICENSE
- github.com/ugorji/go/codec with license MIT

## Memspool

https://github.com/katzenpost/katzenpost/memspool with license AGPL-3.0

depends on:

- github.com/katzenpost/katzenpost/client with license AGPL-3.0
- github.com/katzenpost/katzenpost/core with license AGPL-3.0
- github.com/katzenpost/kimchi with license AGPL-3.0
- github.com/katzenpost/katzenpost/server with license AGPL-3.0
- go.etcd.io/bbolt with license MIT
- github.com/stretchr/testify with license MIT
- github.com/ugorji/go/codec with license MIT
- gopkg.in/op/go-logging.v1 with license BSD-3-Clause

## Registration Client

https://github.com/katzenpost/katzenpost/registration_client with license AGPL-3.0

This component will hopefully go away soon but we include it for
completeness.

depends on:

- github.com/katzenpost/katzenpost/core with license AGPL-3.0
- github.com/katzenpost/katzenpost/server with license AGPL-3.0
- golang.org/x/net with license https://github.com/golang/net/blob/master/LICENSE
