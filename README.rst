
Reunion Library
===============

Reunion is a cryptographic protocol allowing an asynchronous n-way
passphrase authenticated exchange facilitated by the Reunion
server. Compared to PANDA it's much better because it leaks less
metadata and resists precomputational attacks by the server.


Status
------

Work-in-progress.


Cryptographic Primitives
------------------------

* lioness: https://git.schwanenlied.me/yawning/lioness
* AEZ: git.schwanenlied.me/yawning/aez.git
* chacha20+poly1305 aead: https://git.schwanenlied.me/yawning/chacha20poly1305
                            https://godoc.org/golang.org/x/crypto/chacha20poly1305
* argon2id: https://github.com/synacor/argon2id
* rijndael: https://github.com/katzenpost/panda/blob/master/crypto/rijndael/rijndael.go
* hkdf: https://godoc.org/golang.org/x/crypto/hkdf
* curve25519: https://github.com/katzenpost/core/blob/master/crypto/ecdh/ecdh.go
* elligator: https://github.com/agl/ed25519/blob/master/extra25519/extra25519.go
  Here's the ntor elligator:
  https://github.com/Yawning/obfs4/blob/master/common/ntor/ntor.go


license
=======

AGPL: see LICENSE file for details.
