Katzenpost
**********

.. container:: blockquote

   "An especially problematic excision of the political is the marginalization
   within the cryptographic community of the secure-messaging problem, an
   instance of which was the problem addressed by `David Chaum <https://bib.mixnetworks.org/#chaum-mix>`_. Secure-messaging
   is the most fundamental privacy problem in cryptography: how can parties
   communicate in such a way that nobody knows who said what. More than a
   decade after the problem was introduced, `Rackoff and Simon <http://sci-hub.tw/10.1145/167088.167260>`_ would comment on
   the near-absence of attention being paid to the it." (`Phillip Rogaway, The Moral Character of Cryptographic Work <moralcharacter.html>`_) 

.. image:: /_static/images/katzenpost-overview.jpg
    :alt: Katzenpost Overview
    :align: center


The Katzenpost Free Software Project
====================================

Katzenpost is a free software project. We write mix network protocol
libraries.  What is a mix network? It is an anonymous communications
system... however the word anonymous is problematic because some
government authorities equate anonymity with terrorism. We prefer to
instead call it "network security" because you can feel more secure
when you communicate using traffic analysis resistant communications
protocols.

However we realize we cannot simply write a mix network and core
protocol libraries and expect people to use them. Therefore we are
working towards a demonstration encrypted chat client which will
communicate over our mix network. In the spirit of pond this new chat
client will use PANDA (Phrase Automated Nym Discovery Authentication)
for the key exchange and the Signal Double Ratchet for the end to end
encryption.

Traffic analysis helps governments, corporations and Internet service
providers learn more information about the communication even if it is
encrypted. The goal of protecting the confidentiality of messages is
in fact an orthogonal concern to that of resisting traffic
analysis. In particular we are interested in developing mix network
based communications systems that can be used by everyone to hide
these kinds of communications metadata:

* geographic location
* message sender
* message receiver
* message sent time
* message receive time
* message size
* ordering of messages
* frequency of sent messages
* frequency of received messages

However we also consider bad actors within the mix network as well as
active attackers. Our threat model is very clearly articulated in the
"Loopix Anonymity System" however at the end of each of our design
specification documents we have not only a security section but an
anonymity considersations section as well.

There are many message oriented applications and protocols that could
benefit from using our mix network. For example our mix network is not
only good for chat clients but also other types of applications:

* transporting interactions between CRDTs
* transporting interactions to DHTs
* database transaction anonymization
* 'crypto currency' anonymization, especially Zcash which has shielded transactions
  which are particularly well suited to being used with a mix network transport protocol

For further discussion regarding Zcash usage with Katzenpost please see:
:doc:`zcash`.

Blog
====

..  toctree::
    :maxdepth: 1

    blog/index
     
Documentation
=============

..  toctree::
    :maxdepth: 1

    "Playground" Demo: Client Instructions <downloads>
    Katzenpost Network Operators Handbook <docs/handbook/index>
    docs/glossary
    docs/faq
    docs/specs
    presentations

Development
===========

..  toctree::
    :maxdepth: 1

    contribute
    Getting started in Katzenpost development <docs/HACKING/index>
    docs/setup
    → github.com/katzenpost <https://github.com/katzenpost/>
    → godocs: Go package documentation <https://godoc.org/?q=katzenpost>


Mixnets?!
=========

* :doc:`docs/mixnet_academy/syllabus`
* `Mixnet Bibliography <https://bib.mixnetworks.org>`_
* `Phillip Rogaway, The Moral Character of Cryptographic Work (2015) <moralcharacter.html>`_
* Animation: `Panoramix: What is a mixnet? A Short Introduction <https://www.youtube.com/watch?v=dQtk0NcTseg>`_
* Video: `Claudia Diaz: Lecture on Anonymity Systems (2014) <https://www.youtube.com/watch?v=fhqabqmzpqE>`_
* Video: `Ania Piotrowska presents the Loopix Anonymity System at USENIX Security 2017 <https://www.youtube.com/watch?v=R-yEqLX_UvI>`_
\

* Video: `Ian Goldberg: Sphinx: A Compact and Provably Secure Mix Format (2009) <https://www.youtube.com/watch?v=34TKXELJa2c>`_
* `Katzenpost presentation videos <presentations.html#videos>`_
  
`Team <team.html>`_
===================

`Contact <contribute.html>`_
============================

.. rubric:: Supported by

.. image:: /_static/images/eu-flag.jpg
    :width: 80px
    :alt: European Union flag
    :align: left
    :target: https://panoramix.me/

.. container:: small

    This project has received funding from the European Union’s Horizon 2020 
    research and innovation programme under the Grant Agreement No 653497, 
    Privacy and Accountability in Networks via Optimized Randomized Mix-nets (`Panoramix <https://panoramix.me/>`_)"
    and is part of the `PANORAMIX Framework <https://panoramix.me/>`_.
