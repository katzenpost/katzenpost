
Certificate Format Specification
********************************

| David Stainton

Version 0

.. rubric:: Abstract

This document proposes a certificate format that Katzenpost
mix server and directory authority server will use.

.. contents:: :local:


1. Introduction
===============

Mixes and Directory Authority servers need to have key agility in the
sense of operational abilities such as key rotation and key revocation.
That is, we wish for mixes and authorities to periodically utilize a
long-term signing key for generating certificates for new short-term
signing keys.


1.1 Conventions Used in This Document
-------------------------------------

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [RFC2119]_.


1.2 Terminology
---------------


2. Document Format
==================

The CBOR [RFC7049]_ serialization format is used to serialize
certificates where each field is marked with the following keys in a map:

  * "version" - The certificate version number, starting at 0.

  * "type" - The certificate type, that is a name that designates it's
    intended use. See discussion in the next subsection.

  * "expiration" - Date of expiration.

  * "cert_key_type" - The key types used.

  * "certified_key" - The key which is signed.

  * "fingerprint" - The fingerprint of the identity key which signs
    the ``certified_key``, using blake2b512. [RFC7693]_

  * "signature" - The signature is produced by concatenating the above
    field's values and then signing that with the long-term key.


2.1 Certificate Types
---------------------
    
The certificate ``type`` field indicates the type of certificate.
So far we have only two types:

  * mix certificate
  * directory authority certificate

Both mixes and directory authority servers have a secret, long-term
identity key. This key is ideally stored encrypted and offline, it's
used to sign key certificate documents. Key certificates contain a
medium-term signing key that is used to sign other documents. In the
case of an "authority signing key", it is used to sign vote and
consensus documents whereas the "mix singing key" is used to sign mix
descriptors which are uploaded to the directory authority servers.


2.2. Certificate Key Types
--------------------------

It's more practical to continue using Ed25519 [ED25519]_ keys but it's
also possible that in the future we could upgrade to a stateless hash
based post quantum cryptographic signature scheme such as SPHINCS-256
or SPHINCS+. [SPHINCS256]_


Appendix A. References
======================

Appendix A.1 Normative References
---------------------------------

.. [RFC2119]   Bradner, S., "Key words for use in RFCs to Indicate
               Requirement Levels", BCP 14, RFC 2119,
               DOI 10.17487/RFC2119, March 1997,
               <http://www.rfc-editor.org/info/rfc2119>.

.. [RFC7049]   C. Bormannm, P. Hoffman, "Concise Binary Object Representation (CBOR)",
               Internet Engineering Task Force (IETF), October 2013,
               <https://tools.ietf.org/html/rfc7049>.

.. [RFC7693]  Saarinen, M-J., Ed., and J-P. Aumasson, "The BLAKE2
              Cryptographic Hash and Message Authentication Code
              (MAC)", RFC 7693, DOI 10.17487/RFC7693, November 2015,
              <http://www.rfc-editor.org/info/rfc7693>.

.. [ED25519]  <https://tools.ietf.org/html/rfc8032>.


Appendix A.2 Informative References
-----------------------------------

.. [SPHINCS256] Bernstein, D., Hopwood, D., Hulsing, A., Lange, T.,
                Niederhagen, R., Papachristodoulou, L., Schwabe, P., Wilcox
                O'Hearn, Z., "SPHINCS: practical stateless hash-based signatures",
                <http://sphincs.cr.yp.to/sphincs-20141001.pdf>.
