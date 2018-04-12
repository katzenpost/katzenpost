Katzenpost Decryption Mix Network User Interface Design
*******************************************************

| Yawning Angel
| Claudia Diaz
| Kali Kaneko
| David Stainton

Version 0

.. rubric:: Abstract

This document describes the user interface design of the Katzenpost
mix network.

.. contents:: :local:

1. Introduction
===============

   This user interface is meant to mimic the e-mail experience in
   several ways, by allowing existing e-mail programs to interact with
   a mixnet SMTP submission proxy and a POP3 receive proxy. We will
   also suggest specific e-mail client modifications that will present
   some special mixnet specific indicators to the user.

1.1 Terminology
----------------

   * ``MTA`` - mail transfer agent, refers to a mail server

   * ``SMTP`` - simple mail transfer protocol, this is the protocol
     used by e-mail clients for sending mail [RFC5321]_ [RFC6409]_

   * ``POP3`` - post office protocol version 3, a commonly used protocol
     for retrieving mail from a remote server [RFC1939]_ [RFC2449]_

2. System Overview
==================

   Our messaging system user interface design has the goal of
   satisfying one of the two primary obstacles for user adoption,
   namely interoperability. [ADOPT17]_ What we mean here by
   interoperability is that any e-mail client is able to function
   correctly with our SMTP submission proxy and POP3 retrieval proxy
   components which run locally with the e-mail client.

   We shall also maintain strict adherence to various secure user
   interface design principles such as the "Principle of the Path of
   Least Resistance" which in this context could mean that no extra
   action on the part of the user is required to encrypt a message
   because encryption is used by default all the time. [YEE02]_

   The mix network client is essentially split up into two components
   the SMTP proxy and the POP3 proxy. The POP3 proxy only needs to
   communicate with the mixnet PKI to retrieve the user's mail queue
   connection information whereas the SMTP proxy makes more use of the
   PKI in order to perform mix network path selection, mix key
   retrieval for Sphinx packet composition.

3. Behavior of the SMTP submission proxy
========================================

   Submission proxy three point plan:

   * The SMTP proxy will refuse to queue a message if the recipient's
     key is not available and issue the SMTP error message:

         ``455 Server unable to accommodate parameters``

   * The SMTP proxy will refuse to queue the message if the mixnet is
     not available with the following error message:

         ``450 Requested mail action not taken: mailbox unavailable.``

   * Mail delivery failures will be indicated by the reception of
     bounce messages.

   * The SMTP proxy should announce the availability of the mixnet, so
   that the end-user can receive early feedback about the possibility or
   routing a message via the mixnet, while composing the message. This
   availability can be announced in the capabilities header.


4. Behavior of the POP3 retrieval proxy
=======================================

   ... TBD ...

5. Behavior of the e-mail client / K9mail
=========================================

   This section specifies features and user interfaces changes to the
   K9mail e-mail client software. In principle these changes could be
   done to any existing e-mail client however it should also be
   possible to use an e-mail client without these user interface
   enhancements.

   The e-mail client should feature the ability for the user to send
   messages as multiple identities and their corresponding
   key-pairs. The sender identity is signaled to a recipient via a
   header that is added by the recipient's mixnet client like thus:

      ``X-Katzenpost-Sender: <base64 X25519 identity-key>``

   Clients MUST NOT generate outbound mail with the
   `X-Katzenpost-Sender` header set, and MUST examine
   inbound mail for the presence of such a header, and treat all mails
   received that have the header as potentially mallicious.

6. Recommendations for UX in the client implementations
=======================================================

   When integrating with an existing email application, and being an
   experimental feature, the user will be able to opt-in to mixing
   outgoing email.

   There should be an easy visual indication that one recipient is
   able to receive email through the mixnet, based on the domain part
   of the user identifier belonging to the mixable set announced by
   each provider participating of the mixnet infrastructure, which the
   katzenpost client can retrieve from the PKI.

   In the composing view, the "mixing" icon should be enabled by
   default if the following conditions are met:

   - the user opted-in for the katzenpost capability.  the recipient's
   - domain belongs to the mixable set.  the mixnet status is healthy.

   Even when the switch to route an outgoing email is enabled
   automatically, the user should be able to disable mixnet routing on
   a per-message basis.

   In order to assist the user making the best choices in terms of
   tradeoffs when sending an email, the MUA should be able to display
   some light statistics about the status of the service in a
   non-obstrusive way (ie, mouseover). These statistics would include:

   - the amount of delay to expect when delivering through the mixnet.
   - the percentage of successful deliveries.

   In the mailbox and message views, the "mixing" icon should be
   enabled and green if the mixnet-specific header is present in the
   message. Optionally, this header can be signed by the key of the
   mixnet delivery agent, either by signing the header individually or
   by including that header in a memoryhole-signed payload. If a
   signature is present, the MUA should verify it and display a
   verification mark accordingly.

   In the case of the non-mixed email, the "mixing" icon should be
   enabled and grayed out if the user opted-in for the mixing
   capabilities, or just disabled otherwise.

   In the cases in which the MUA is already displaying the status of
   e2e encryption (like in PGP-enabled MUAs), when deciding the status
   of such visual indication the semantics of e2e encryption in
   katzenpost should also be considered and merged with the other
   status, instead of indicating katzenpost e2e encryption and pgp
   encryption as two separate parts.

Appendix A. References
======================

Appendix A.1 Normative References
---------------------------------

Appendix A.1 Informative References
-----------------------------------

.. [RFC5321] J., Klensin, Network Working Group, Standards Track,
             October 2008, "Simple Mail Transfer Protocol",
             <https://tools.ietf.org/html/rfc5321>.

.. [RFC6409] J., Klensin, R., Gellens, Internet Engineering Task Force, Standards Track,
             November 2011, "Message Submission for Mail",
             <https://tools.ietf.org/html/rfc6409>.

.. [RFC1939] J., Myers, M., Rose,
             May 1996, "Post Office Protocol - Version 3",
             <https://tools.ietf.org/html/rfc1939>.

.. [RFC2449] R., Gellens, C., Newman, L., Lundblade, Network Working Group, Standards Track,
             November 1998, "POP3 Extension Mechanism",
             <https://tools.ietf.org/html/rfc2449>.

.. [ADOPT17] Bonneau, J., Sasse, M., Abu-Salma, R., Smith, M., Naiakshina, A., Danilova, A.
             "Obstacles to the Adoption of Secure Communication Tools",
             Proceedings of the 38th IEEE Symposium on Security and Privacy,
             Oakland, San Jose, CA, USA, 2017
             <http://www.jbonneau.com/doc/ASBDNS17-IEEESP-secure_messaging_obstacles.pdf>.

.. [YEE02] Yee, Ka-Ping., "User Interaction Design for Secure Systems",
           Computer Science Department, University of California, Berkeley,
           May 2002, <http://zesty.ca/pubs/csd-02-1184.pdf>.
