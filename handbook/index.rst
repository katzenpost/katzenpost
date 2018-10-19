
Katzenpost Handbook
*******************

| David Stainton

Version 0

.. rubric:: Abstract

Thank you for interest in Katzenpost! This document describes how to
use and configure the Katzenpost Mix Network software system. The
target audience for this document is systems administrators. This
document assumes you are familiar with using unix systems, git
revision control system and building golang binaries.

.. contents:: :local:


Introduction
============

Katzenpost can be used as a message oriented transport for a variety
of applications and is in no way limited to the e-mail use case
demonstrated by the ``mailproxy`` client/library. Other possible
applications of Katzenpost include but are not limited to: instant
messenger applications, crypto currency transaction transport,
bulletin board systems, file sharing and so forth.

The Katzenpost system has four component categories:

* public key infrastructure
* mixes
* Providers
* clients

Providers has a superset of mixes that fulfill two roles:
1. The initial hop in the route and therefore as an ingress hop
   this node authenticates clients and does per client rate limiting.
2. The terminal hop in the route and therefore can either store and
   forward or proxy to a ``Kaetzchen`` aka a mixnet service.


This handbook will describe how to use and deploy each of these.
The build instructions in this handbook assume that you have a proper
golang environment with at least golang 1.10 or later AND the git
revision control system commandline installed.


Building the latest stable version of Katzenpost
------------------------------------------------

NOTE: Find out what our latest stable version tag
by looking at the "releases.rst" file in the top-level
of this repository.


0. Acquire a recent version of dep: https://github.com/golang/dep

1. Clone the Katzenpost daemons repository::

     mkdir $GOPATH/github.com/katzenpost
     git clone https://github.com/katzenpost/daemons.git

2. Checkout the latest stable release tag::

     cd $GOPATH/github.com/katzenpost/daemons
     git checkout v0.0.1 # replace v0.0.1 with latest version tag

2. Fetch the Katzenpost vendored dependencies::

     dep ensure

3. Build the binaries::

     (cd authority/nonvoting; go build)
     (cd server; go build)
     (cd mailproxy; go build)


The Katzenpost Configuration File Format
----------------------------------------

Each Katzenpost component has a configuration file in the TOML format.
This handbook will give you all the details you need to know to configure
each of these configuration files. To learn more about the TOML format
see: https://github.com/toml-lang/toml#toml

NOTE: ``#`` may be used at the beginning of a line to denote a comment
instead of an effective configuration line.


Example Katzenpost Configuration Files
--------------------------------------

Sample Katzenpost configuration files are located in our ``daemons``
git repository under the component's corresponding subdirectory:

* https://github.com/katzenpost/daemons


Notes on Building a Test Mix Network
------------------------------------

Providers, mixes and the Directory Authority are distinct components
of a Katzenpost mix network which SHOULD be deployed on separate
server machines. If you are building a test network on a single
machine then all mix network components must have differing network
endpoints; that is, if their IP addresses do not differ then their TCP
port numbers must be different.



