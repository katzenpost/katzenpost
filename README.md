# Katzenpost Mix Network

## Post Quantum Anonymous Communication Network

![build badge](https://github.com/katzenpost/katzenpost/actions/workflows/go.yml/badge.svg?branch=main)

Katzenpost is a software project dedicated to designing and
implementing mix network protocols. A mix network is a type of
anonymous communication network. An anonymous communication
network is also known as a traffic analysis resistant network; that is,
it's protocols are designed to resist statistical analysis by passive
global adversaries.

Traffic analysis typically refers to the statistical analysis of
encrypted traffic. Traffic analysis is worth defending against given
that common network protocols leak lots of information such as source
and destination IP addresses, message size, message sequence, message
delay pattern, geographical locations, social graph etc. Mere end to
end encryption alone cannot protect against this type of information
leakage.

At the most basic level, mixnets are composed of mix nodes. These are
a cryptographic packet switching routers which protect our privacy by
mixing many messages together and cryptographically transforming them
before routing them on to the next hop. Mix nodes also use shuffling
or added latency to create uncertainty for network observers. This
uncertainty is in regards to trying to link incoming messages with the
outgoing messages.


# Project Status

Many excited new changes are forthcoming!
You can watch our progress being tracked, here:

https://github.com/orgs/katzenpost/projects/6/views/5


# Building Katzenpost

To build all server related components, type "make" when inside this repo:

```bash
cd katzenpost
make
```

# Client:

Currently, [Katzen](https://github.com/katzenpost/katzen) is the only client available for use with Katzenpost. However a SOCKS proxy client is forthcoming
and you'll be able to use that with many existing applications.

# Server Side Usage/Configuration

Our docker configuration is the most comprehensive and up to date
place to learn about how to configure a Katzenpost mix network. Run
the makefile in the docker directory to get a usage menu:

```bash
$ cd katzenpost/docker; make 
These make targets allow you to control the test network:
 run                - run the testnet in the foreground, until ctrl-C
 start              - start the testnet in the background
 stop               - stop the testnet
 wait               - wait for testnet to have consensus
 watch              - tail -F all logs
 status             - show testnet consensus status
 show-latest-vote   - does what it says
 run-ping           - send a ping over the testnet
 clean-local        - stop, and delete data and binaries
 clean-local-dryrun - show what clean-local would delete
 clean              - the above, plus cleans includes go_deps images
```

**You can run a docker mixnet locally and then inspect the configuration files
to learn how to configure a Katzenpost mixnet.**


Documentation is a work in progress:

* [mix server docs](docs/handbook/mix_server.rst)

* [dirauth server docs](docs/handbook/voting_pki.rst)



# Expert's Corner

Katzenpost is an unverified decryption mix network that uses a continuous time
mixing strategy with client selected exponential delays and a stratified (layered) topology. 

Our documentation is in progress, but we have some resources for experts:

* Out mix net design literature review, can be found [here.](https://katzenpost.network/research/Literature_overview__website_version.pdf)

* Our threat model document, work-in-progress, can be found [here.](https://katzenpost.network/research/Threat_Model_Doc.pdf)

* Our design specification documents are available [here.](https://github.com/katzenpost/katzenpost/tree/main/docs/specs)


## Cryptographic Agility

Katzenpost consists of 3 core cryptographic protocols all of which have cryptographic agility
with respect to the KEM, NIKE or signature scheme being used:

1. Wire protocol based on Noise/PQ Noise
2. Sphinx
3. PKI

Each of these protocols makes use of our golang cryptography library called HPQC (hybrid post quantum cryptography):

https://github.com/katzenpost/hpqc

Firstly, for each of the protocols we make use of a small set of
golang interfaces for KEM, NIKE and signature schemes respectively
allowing us to build protocols that are completely agnostic to the
specific cryptographic primitive being used.  Secondly, each of these
protocol implementations allows for the selection of the cryptographic
primitive via it's TOML configuration file.


## Wire protocol based on Noise/PQ Noise

All Katzenpost components communicate with one another using our
"wire" protocol which currently only works on TCP but hopefully soon also QUIC.
This wire protocol is traffic padded as a redundant measure against traffic analysis.

We believe in [The Noise Protocol Framework](https://noiseprotocol.org/), that it is
good to use it instead of TLS, whenever possible. Noise places all of
the protocol decision making during the design phase of the protocol
instead of during protocol runtime. This means there are no protocol
downgrade attacks, no dynamic selection of ciphersuite and so on.

However, we use a variation of Noise called [Post Quantum Noise](https://eprint.iacr.org/2022/539.pdf), from the paper:

```
@misc{cryptoeprint:2022/539,
      author = {Yawning Angel and Benjamin Dowling and Andreas Hülsing and Peter Schwabe and Florian Weber},
      title = {Post Quantum Noise},
      howpublished = {Cryptology ePrint Archive, Paper 2022/539},
      year = {2022},
      doi = {10.1145/3548606.3560577},
      note = {\url{https://eprint.iacr.org/2022/539}},
      url = {https://eprint.iacr.org/2022/539}
}
```

Our wire protocol implementation let's you select any KEM and if you
happened to have selected Xwing then the precise Noise protocol
descriptor string for the protocol would be:

``Noise_pqXX_Xwing_ChaChaPoly_BLAKE2s``

Here's a diagram of the pqXX pattern which we use:

```mermaid
sequenceDiagram
    Client-)Server: e
    Server-)Client: ekem, s
    Client-)Server: skem, s
    Server-)Client: skem
```

## Sphinx

We use the Sphinx cryptographic packet format and allow it's geometry
to be completely configurable to accomodate various networking
requirements. Additionally the Sphinx can use any NIKE
(non-interactive key exchange). We also developed a novel post quantum
variation called KEM Sphinx. KEM (key encapsulation mechanism) Sphinx
is twice as fast on the server side as the original NIKE Sphinx
because it only requires one public key operation per hop instead of
two. However it has the packet header overhead size penalty that grows
linearly with the number of hops.

And here are some Sphinx benchmarks using different KEMs and NIKEs, computed on David's laptop:

| Primitive | Sphinx type | nanoseconds/op |
| :---      |  :---:      |     ---:       |
| X25519 | NIKE | 144064 |
| X448 | NIKE | 131322 |
| X25519 CTIDH512 | NIKE | 256711856 |
| X25519 | KEM | 55718 |
| Xwing | KEM | 172559 |
| MLKEM768-X25519 | KEM | 173413 |

We can draw several conclusions from this table of benchmarks:

1. KEM Sphinx is about twice as fast as NIKE Sphinx
2. MLKEM768 is faster than X25519
3. Xwing KEM Sphinx is almost as fast as X25519 NIKE
   Sphinx but probably a lot more secure given that it's a post quantum
   hybrid construction which still uses the classically secure X25519
   NIKE.
4. CTIDH is very slow and we probably don't want to use it for
   Sphinx. We instead think it very useful for application level
   encryption.

Please also note that hybrid KEMs referred to above are constructed
using a security preserving KEM combiner and a NIKE to KEM adapter (adhoc elgamal construction)
with semantic security so that the resulting hybrid KEM is IND-CCA2 in the QROM.

## PKI/Directory Authority

Mix network key management and distribution is handled by the
directory authority system, a decentralized voting protocol that can
tolerate (1/2 * n)-1 node outages.  Clients and mix nodes can talk to
the dirauth (directory authority) system to get a published PKI document which is
essentially a view of the network which contains public cryptographic
keys and network connection information.

The mix descriptors are signed by the mix nodes. Each dirauth also signs their
interactions in the voting protocol and the final published PKI document.

Mix nodes and dirauth (directory authority) nodes use whichever signature scheme selected
by the dirauth configuration. Clients also use this signature scheme to verify PKI documents.


# Debugging/Profiling Katzenpost

We can optionally enable the use of pyroscope pprof profiling within the mix server
by building with the "pyroscope" build tag:

cd server/cmd/server; go build --tags pyroscope

You'll have to setup a pyroscope server via these instructions, here:

https://grafana.com/docs/pyroscope/latest/get-started/

And you can point the mix server at the pyroscope server via environment variables:

```bash
export PYROSCOPE_APPLICATION_NAME=katzenpost_mix_server
export PYROSCOPE_SERVER_ADDRESS=http://localhost:4040
export PYROSCOPE_SERVICE_TAG=mix1
./server -f katzenpost-server.toml
```


# License

AGPLv3

# Donations

Your donations are welcomed and can be made through Open Collective [here.](https://opencollective.com/the-katzenpost-software-project)


# Supported By

[![NGI](https://katzenpost.mixnetworks.org/_static/images/eu-flag-tiny.jpg)](https://www.ngi.eu/about/)
<a href="https://nlnet.nl"><img src="https://nlnet.nl/logo/banner.svg" width="160" alt="NLnet Foundation"/></a>
<a href="https://nlnet.nl/assure"><img src="https://nlnet.nl/image/logos/NGIAssure_tag.svg" width="160" alt="NGI Assure"/></a>
<a href="https://nlnet.nl/NGI0"><img src="https://nlnet.nl/image/logos/NGI0PET_tag.svg" width="160" alt="NGI Zero PET"/></a>

This project has received funding from:

* European Union’s Horizon 2020 research and innovation programme under the Grant Agreement No 653497, Privacy and Accountability in Networks via Optimized Randomized Mix-nets (Panoramix).
* The Samsung Next Stack Zero grant.
* NGI0 PET Fund, a fund established by NLnet with financial support from the European Commission's Next Generation Internet programme, under the aegis of DG Communications Networks, Content and Technology under grant agreement No 825310.
* NGI Assure Fund, a fund established by NLnet with financial support from the European Commission's Next Generation Internet programme, under the aegis of DG Communications Networks, Content and Technology under grant agreement No 957073.

