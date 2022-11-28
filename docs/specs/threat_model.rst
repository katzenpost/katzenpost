Katzenpost Threat Model
***********************
| David Stainton

| Version 0

.. rubric:: Abstract

Here we describe the threat model of the katzenpost mix network transport protocol
and also discuss threat models for addition protocol layers.
	    
.. contents:: :local:

Overview of Mix Network Threat Model
====================================

Mixnets provide the Anytrust property which means that if a route
consists of at least one honest mix then there is still uncertainty
for a passive network observer for the correlation between sent and
received messages. This of course is predicated on the assumption that
the mixnet has sufficient traffic from a sufficient number of users.
Conversely, if an adversary has compromised the entire route it is then
defined to be a bad route and implies immediate correlation between sent
and received messages.

Given that Katzenpost is designed for the asynchronous messaging use
case, it's remarkable that queueing messages at the edge of the
network also implies that classical intersection attacks with full
granularity involve compromising one or more Providers whereas most of
the mixnet literature on the topic assumes different situation where
message flows to clients are visible by passive network observers. In
Loopix and Katzenpost this is not the case because of the queueing and
the traffic padded protocol used by clients to retreive messages.

The adversary needs to compromise the Providers in order to learn
which client's message queue received a given message. Without this
information, intersection attacks would take much longer because
Providers can have many client message queues which would make passive
network observations contain a low amount of statistical
information. We can therefore say that even if the adversary
compromises the sending Provider and the receiving Provider that this
would only allow the adversary perform an intersection attack and
would not immediately allow linking senders with the receivers if the
mix network had enough users and enough traffic (mix entropy).

There is a hierarchy of security notions that are used by
cryptographers to compare cryptographic primitives. Likewise, a
hierarchy of privacy notions help us compare anonymous communication
protocols. See [NOTIONS]_ for an in depth discussion and algebraic
analsysis on privacy notions for anonymous communication protocols.

At the time of writing it is my understanding that the mixnet protocols
we want to see in the world would have these privacy notions:

1. Sender Unobservability
2. Receiver Unobservability
3. Sender Receiver Unlinkability

The end to end messaging protocol layered on top of katzenpost will of
course use end to end encryption and so we must also consider
discussions about violating the security notions of such an
application as well. We do intend to discuss breaking our protocol
stack in both the high and the lower protocol layers.
   
In the following discussions of the various attacks we'll need to try
and relate it back to how the attack violates one or more of the above
privacy notions. It is this set of privacy notions which represent
what we really mean when we say "anonymous".

Our threat model will consider the following eight categories of attacks:

1. n-1 attacks
2. epistemic attacks
3. compulsion attacks
4. tagging attacks
5. statistical disclosure attacks
6. denial of service attacks
7. timing attacks
8. cryptographic attacks (including considerations regarding
   cryptographic attacks by a sufficiently powerful quantum
   computational adversary)

As of the time of this writing, ALL mixnet attacks that we know about fit
into one or more of the above categories or composite attacks, a
combination of several of the above attacks.




1. n-1 Attacks
==============

2. epistemic attacks
====================

3. compulsion attacks
=====================

4. tagging attacks
==================

5. statistical disclosure attacks
=================================

6. denial of service attacks
============================

7. timing attacks
=================

8. cryptographic attacks
========================



Appendix A. References
======================

Appendix A.1 Normative References
---------------------------------

.. [NOTIONS]   Christiane Kuhn, Martin Beck, Stefan Schiffner,
	       Eduard Jorswieck and Thorsten Strufe,
               PETS 2019,
               <https://petsymposium.org/2019/files/papers/issue2/popets-2019-0022.pdf>.

	       

