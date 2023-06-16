# Katzenpost Mix Network

## Post Quantum Anonymous Communication Network

![build badge](https://github.com/katzenpost/katzenpost/actions/workflows/go.yml/badge.svg?branch=main)

Katzenpost is a software project dedicated to designing and implementing
mix network protocols. A mix network is a type of anonymous communication network
that is message oriented rather than stream oriented in it's design.

We build anonymous protocols so that everyone can communicate more freely
in this age of pervasive surveillance.

Our model of Katzenpost as three cryptographic protocols layers:

1. Post Quantum Noise cryptographic protocol
that routes messages over the Internet. Can use either TCP or QUIC.

2. Post Quantum NIKE/KEM Sphinx cryptographic packet protocol layer
   which mixes, routes and cryptographically transforms Sphinx packets at each hop.

3. Post Quantum cryptographic application protocol layer, for example,
   post quantum double ratchet that uses a hybrid NIKE with CTIDH and X25519.


# Project Status

**A status update is forthcoming!**

![Katzenpost architecture diagram](diagrams/katzenpost_architecture.png)


## Easy One Step BUILD

All you have to do is type:

```bash
make
```

For Docker users, you can use:

```bash
make docker
```


# Expert's Corner

Our documentation is in progress, but we have some resources for experts:


* Our threat model document, work-in-progress, can be found [here.](https://raw.githubusercontent.com/katzenpost/katzenpost/add_threat_model_doc/docs/specs/threat_model.rst)

* Our design specification documents are available [here.](https://github.com/katzenpost/katzenpost/tree/main/docs/specs)


# Contribute


# Donations

Your donations are welcomed and can be made through Open Collective [here.](https://opencollective.com/the-katzenpost-software-project)


### Supported By

This project has received funding from:

* European Union’s Horizon 2020 research and innovation programme under the Grant Agreement No 653497, Privacy and Accountability in Networks via Optimized Randomized Mix-nets (Panoramix).
![tiny eu flag](https://katzenpost.mixnetworks.org/_static/images/eu-flag-tiny.jpg)
* The Samsung Next Stack Zero grant
* NLnet and the NGI0 PET Fund paid for by the European Commission


