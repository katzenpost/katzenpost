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

Goals
=====

* to *prevent* a sufficiently global passive adversary from learning who is communicating with whom
* to *detect* active attacks against the network infrastructure
* hide message content from participating providers, hide recipient identity from the sender's provider, and the sender identity from the recipient's provider
* reliable out of order delivery
* support for various "message based" use cases like 'instant messaging', 'e-mail', and 'crypto currency' anonymization

Non-Goals
=========

* to hide the sender identity from the final recipient

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

* `Mixnet Bibliography <https://bib.mixnetworks.org>`_
* `Phillip Rogaway, The Moral Character of Cryptographic Work (2015) <moralcharacter.html>`_
* Animation: `Panoramix: What is a mixnet? A Short Introduction <https://www.youtube.com/watch?v=dQtk0NcTseg>`_
* Video: `Claudia Diaz: Lecture on Anonymity Systems (2014) <https://www.youtube.com/watch?v=fhqabqmzpqE>`_
\

* Video: `Ian Goldberg: Sphinx: A Compact and Provably Secure Mix Format (2009) <https://www.youtube.com/watch?v=34TKXELJa2c>`_
* `Katzenpost presentation videos <presentations.html#videos>`_
  
`Team <team.html>`_
===================

`Contact <contribute.html>`_
============================

.. rubric:: Supported by

.. image:: /_static/images/eu-flag.jpg
    :width: 70px
    :alt: European Union flag
    :align: left
    :target: https://panoramix-project.eu/

.. container:: small

    This project has received funding from the European Union’s Horizon 2020 
    research and innovation programme under the Grant Agreement No 653497, 
    Privacy and Accountability in Networks via Optimized Randomized Mix-nets (Panoramix)".
