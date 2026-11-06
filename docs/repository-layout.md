# Repository layout

Back to the [README](../README.md). Part of [Engineering Katzenpost](ENGINEERING.md).

This repository is one Go module. Each top-level directory is a library shared between
components, a long-lived component (mix server, directory authority, courier, replica, client
daemon), or an entry point under `cmd/`.

```
katzenpost/
├── cmd/                       # One directory per binary
│   ├── server/                # Mix node: gateway, mix or service node
│   ├── dirauth/               # Directory authority
│   ├── kpclientd/             # Client daemon
│   ├── courier/               # Pigeonhole courier (a service node plugin)
│   ├── replica/               # Pigeonhole replica
│   ├── voucher-router/        # Contact voucher router (a service node plugin)
│   ├── service-directory/     # Pigeonhole service directory (a service node plugin)
│   ├── echo-plugin/           # Echo service plugin, an example
│   ├── http-proxy-client/     # HTTP over the mixnet, client side
│   ├── http-proxy-server/     # HTTP over the mixnet, service plugin
│   ├── genconfig/             # Generates a network's TOML configuration
│   ├── kpconfig/              # Validates configuration files
│   ├── genkeypair/            # Generates key pairs
│   ├── geometry/              # Generates Sphinx and Pigeonhole geometries
│   ├── fetch/                 # Fetches documents from the directory authorities
│   ├── ping/                  # Round trip through the mixnet
│   ├── motd/                  # Fetches the network's message of the day
│   ├── sphinx/                # Sphinx packet tool
│   └── internal/mixclient/    # Client code shared by ping and motd
│
├── core/                      # Primitives shared by every component
│   ├── sphinx/                # Sphinx packet format, NIKE and KEM variants
│   ├── wire/                  # PQ Noise wire protocol
│   ├── pki/                   # PKI document types and verification
│   ├── cert/                  # Multi-signature certificates
│   ├── epochtime/             # Epoch arithmetic
│   ├── genconfig/             # Configuration generation library
│   ├── connlimit/             # Connection limits
│   ├── selfcheckcache/        # Cached startup self-check measurements
│   ├── log/, queue/, retry/, thwack/, utils/, worker/, compat/
│   └── copyright              # Copyright notice for the wire packages
│
├── authority/voting/          # Directory authority: voting PKI
│   ├── client/                # PKI client used by nodes and clients
│   ├── server/                # The voting server
│   └── tla/                   # TLA+ model of the voting protocol
│
├── server/                    # Mix node
│   ├── config/                # TOML schema
│   ├── internal/              # Gateway, incoming and outgoing links, Sphinx workers,
│   │                          #   scheduler, decoy traffic, mix keys, PKI, service plugins
│   ├── cborplugin/            # CBOR-over-stdio plugin protocol
│   ├── spool/                 # Gateway spool
│   └── tla/                   # TLA+ models of the mix node
│
├── client/                    # kpclientd
│   ├── thin/                  # Go thin client (Rust and Python are in thin_client)
│   ├── config/, transport/    # TOML schema; daemon-to-gateway transport
│   ├── arq.go, daemon.go      # Retransmission, connection state, dispatch
│   ├── pigeonhole.go          # Pigeonhole channels in the daemon
│   └── tla/                   # TLA+ model of the ARQ
│
├── courier/server/            # Courier: replica fan-out and copy state
├── replica/                   # Replica (Pebble), with integration and model tests
├── pigeonhole/                # Pigeonhole messages (trunnel) and geometry
├── pigeonservice/             # Services built on Pigeonhole: discovery, voucher router
├── quic/                      # QUIC links (net.Conn over QUIC) and the HTTP proxy commands
├── loops/                     # Decoy-loop statistics types
├── common/                    # CLI, configuration, metrics and strict TOML helpers
├── bacap/, hpqcfuzz/         # Fuzz targets for BACAP and the hpqc schemes
├── fuzz/                      # Fuzzing kit: Makefile, seeds, corpus
├── tools/                     # mixnet-params (Python capacity calculator), chaos
├── docker/                    # Local test network
├── debian/, packaging/        # Debian packages and their build and test scripts
└── docs/                      # This guide
```

## Pigeonhole in this repository

Pigeonhole gives applications asynchronous communication over the mixnet. A client never talks
to a replica directly. Each Pigeonhole operation is a Sphinx round trip through the mix layers
to a courier on a service node, and the courier forwards it to the replicas responsible for the
Box. Each Box goes to two replicas, chosen by consistent hashing. Replicas keep Boxes for the
current and the previous replica epoch, so a Box lasts between one and two weeks.

The courier is `courier/` and `cmd/courier`; the replica is `replica/` and `cmd/replica`; the
messages they exchange are in `pigeonhole/`. BACAP, which derives Box identifiers and the read
and write capabilities, is in [hpqc](https://github.com/katzenpost/hpqc) under `bacap/`. The
design is §§4-5 of the [Echomix paper](https://arxiv.org/abs/2501.02933) and the
[Pigeonhole specification](https://katzenpost.network/docs/specs/pigeonhole/).
