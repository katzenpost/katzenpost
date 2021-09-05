
=======
Reunion
=======

.. image:: https://godoc.org/github.com/katzenpost/katzenpost/reunion?status.svg
  :target: https://godoc.org/github.com/katzenpost/katzenpost/reunion

.. image:: https://api.codacy.com/project/badge/Grade/fa6651c5ed42478ca07c330faf5001c6
  :target: https://www.codacy.com/gh/katzenpost/reunion?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=katzenpost/reunion&amp;utm_campaign=Badge_Grade


Reunion is a cryptographic protocol allowing an asynchronous
passphrase authenticated exchange facilitated by the Reunion
server acting as a broadcast channel and ciphertext intermediary.
Compared to PANDA it's much better because it leaks less
metadata and resists precomputational attacks by the server.


Status
------

This cryptographic library is in working order.
However the Server doesn't have enough tests yet.

There are two servers written so far:

1. HTTP Reunion server
2. Katzenpost mix server plugin


Katzenpost mix server plugin
----------------------------

To configure your katzenpost provider, add the following lines to your
configuration file in the [Provider] section, with the appropriate paths.

::

  [[Provider.CBORPluginKaetzchen]]
    Capability = "reunion"
    Endpoint = "+reunion"
    Command = "/path/to/reunion_katzenpost_server"
    MaxConcurrency = 1
    [Provider.CBORPluginKaetzchen.Config]
      log_level = "NOTICE"
      log = "/path/to/reunion.log"
      s = "/path/to/reunion.storage"


Cryptographic Primitives
------------------------

* AEZ: git.schwanenlied.me/yawning/aez.git
* chacha20+poly1305 aead: https://git.schwanenlied.me/yawning/chacha20poly1305
* argon2id: https://godoc.org/golang.org/x/crypto/argon2
* hkdf: https://godoc.org/golang.org/x/crypto/hkdf
* curve25519: https://github.com/katzenpost/katzenpost/blob/master/core/crypto/ecdh/ecdh.go
* elligator: https://github.com/katzenpost/katzenpost/blob/master/core/crypto/extra25519/extra25519.go


disclaimer
==========

Thus far there are not been very much code review and no formal security audit of this code.

DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.


license
=======

AGPL: see LICENSE file for details.
