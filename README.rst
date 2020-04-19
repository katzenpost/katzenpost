

.. image:: https://travis-ci.org/katzenpost/doubleratchet.svg?branch=master
  :target: https://travis-ci.org/katzenpost/doubleratchet

.. image:: https://godoc.org/github.com/katzenpost/doubleratchet?status.svg
  :target: https://godoc.org/github.com/katzenpost/doubleratchet

Double Ratchet Library
======================

This library is a fork of agl's double ratchet in his pond messaging system.
We have made several changes in this fork:

* serialization in CBOR instead of protobufs
* this library takes ownership of all key material used
* added methods to perform the complete key exchange
  whereas in pond the code to perform the key exchange was
  spread out and not at all contained with the ratchet code module.

Read **The Double Ratchet Algorithm** by Trevor Perrin (editor), Moxie Marlinspike
https://signal.org/docs/specifications/doubleratchet/


Contact
=======

* IRC: irc.oftc.net #katzenpost <irc://irc.oftc.net/#katzenpost>
* Mailing List <https://lists.mixnetworks.org/listinfo/katzenpost>

Disclaimer
==========

I am not certain to the degree agl's ratchet was audited however
I shall state here that my modifications to this code has NOT been audited
for security vulnerabilities. Therefore this library should be not considered
correct or safe to use. Proceed with caution.

License
=======

This is a fork of agl's double ratchet:
https://github.com/agl/pond/tree/master/client/ratchet

We do not claim any endorsement or approval from agl or pond, obviously.
Please see agl's LICENSE file for details, which is included in this repository
as per the legal requirements of the software license.

Please also note that this license includes a copyright:

Copyright (c) 2013 Adam Langley. All rights reserved.
