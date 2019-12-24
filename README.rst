
=======
Reunion
=======

.. image:: https://godoc.org/github.com/katzenpost/reunion?status.svg
  :target: https://godoc.org/github.com/katzenpost/reunion

.. image:: https://api.codacy.com/project/badge/Grade/fa6651c5ed42478ca07c330faf5001c6
  :target: https://www.codacy.com/gh/katzenpost/reunion?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=katzenpost/reunion&amp;utm_campaign=Badge_Grade


Reunion is a cryptographic protocol allowing an asynchronous n-way
passphrase authenticated exchange facilitated by the Reunion
server. Compared to PANDA it's much better because it leaks less
metadata and resists precomputational attacks by the server.


Status
------

Work-in-progress.

The core cryptographic operations are in working order at this
time. There are some unit tests and bench marks which demonstrate the
basic protocol interaction between two clients.


Cryptographic Primitives
------------------------

* AEZ: git.schwanenlied.me/yawning/aez.git
* chacha20+poly1305 aead: https://git.schwanenlied.me/yawning/chacha20poly1305
* argon2id: https://godoc.org/golang.org/x/crypto/argon2
* hkdf: https://godoc.org/golang.org/x/crypto/hkdf
* curve25519: https://github.com/katzenpost/core/blob/master/crypto/ecdh/ecdh.go
* elligator: https://github.com/agl/ed25519/blob/master/extra25519/extra25519.go

license
=======

AGPL: see LICENSE file for details.
