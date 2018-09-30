Katzenpost
**********

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

    "Playground" Demo: Client Instructions <https://github.com/katzenpost/playground/blob/master/README.rst>
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
* Animation: `Panoramix: What is a mixnet? A Short Introduction <https://www.youtube.com/watch?v=dQtk0NcTseg>`_
* Video: `Claudia Diaz: Lecture on Anonymity Systems (2014) <https://www.youtube.com/watch?v=fhqabqmzpqE>`_
* Video: `Ian Goldberg: Sphinx: A Compact and Provably Secure Mix Format (2009) <https://www.youtube.com/watch?v=34TKXELJa2c>`_
* Video: `David Stainton: BornHack 2018 - Modern Mix Network Design <https://www.youtube.com/watch?v=DhBWKWQztdA>`_
* Video: `Jeff Burdges and David Stainton 34C3 - Practical Mix Network Design <https://www.youtube.com/watch?v=O_mlX1rV2DQ>`_
* Video: `David Stainton: Anonymizing Cryptocurrencies from Network Observers with Mix Networks <https://www.youtube.com/watch?v=dSydsoCe_SA>`_
* Video: `David Stainton Shows How Mix Networks Improve Privacy <https://www.youtube.com/watch?v=7zIWrNqiTLI>`_
  
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
