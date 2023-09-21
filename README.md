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


There are essentially two types of interaction with a Katzenpost mixnet:
1. clients talk to mixnet services and their traffic stays in the mixnet
2. clients talk to Internet services; proxying through the mixnet onto the Internet.

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

* Our threat model document, work-in-progress, can be found [here.](https://raw.githubusercontent.com/katzenpost/katzenpost/add_threat_model_doc/docs/specs/threat_model.rst)

* Our design specification documents are available [here.](https://github.com/katzenpost/katzenpost/tree/main/docs/specs)

## Wire protocol based on Noise

Every component in a Katzenpost mix network uses our "wire" protocol, the protocol that sits on top of either TCP or QUIC, is a cryptographic protocol based on Noise:

[The Noise Protocol Framework](https://noiseprotocol.org/)

We believe in the Noise cryptographic protocol framework, that it is
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

The precise Noise protocol descriptor string we use is:

``Noise_pqXX_Kyber768X25519_ChaChaPoly_BLAKE2s``

However the hybrid KEM Kyber768X25519 is constructed using a security
preserving KEM combiner and a NIKE to KEM adapter with semantic
security so that the resulting hybrid KEM is IND-CCA2 in QROM.

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

And here are some Sphinx benchmarks using different KEMs and NIKEs:

| Primitive | Sphinx type | nanoseconds/op | seconds/op |
| :---      |  :---:      |     ---:       | ---:       |
| X25519 | KEM | 80093 | 8.009×10−5 |
| X25519 | NIKE | 160233 | 0.000160233 |
| Kyber512 | KEM | 43758 | 4.3758e-5 |
| Kyber768 | KEM | 57049 | 5.7049e-5 |
| Kyber1024 | KEM | 72173 | 7.2173e-5 |
| Kyber768 X25519 Hybrid | KEM | 87816 | 8.7816e-5 |
| CTIDH512 | NIKE | 336995975 | 0.336995975 |
| CTIDH1024 | NIKE | 18599579037 | 18.599579037 |
| CTIDH2048 | NIKE | 17056742100 | 17.0567421 |
| CTIDH1024 | KEM | 11408217346 | 11.408217346 |

We can draw several conclusions from this table of benchmarks:

1. KEM Sphinx is about twice as fast as NIKE Sphinx
2. Kyber768 is faster than X25519
3. Kyber768 X25519 Hybrid KEM Sphinx is almost as fast as X25519 NIKE
   Sphinx but probably a lot more secure given that it's a post quantum
   hybrid construction which still uses the classically secure X25519
   NIKE.
4. CTIDH is very slow and we probably don't want to use it for
   Sphinx. We instead think it very useful for application level
   encryption.

Please also note that hybrid KEMs referred to above are constructed
using a security preserving KEM combiner and a NIKE to KEM adapter
with semantic security so that the resulting hybrid KEM is IND-CCA2 in
QROM.

## PKI/Directory Authority

Mix network key management and distribution is handled by the
directory authority system, a decentralized voting protocol that can
tolerate (1/2 * n)-1 node outages.  Clients and mix nodes can talk to
the dirauth system to get a published PKI document which is
essentially a view of the network which contains public cryptographic
keys and network connection information.

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

