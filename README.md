# katzenpost

[![Go Reference](https://pkg.go.dev/badge/github.com/katzenpost/katzenpost.svg)](https://pkg.go.dev/github.com/katzenpost/katzenpost)
[![linux unit tests](https://github.com/katzenpost/katzenpost/actions/workflows/linux.yml/badge.svg?branch=main)](https://github.com/katzenpost/katzenpost/actions/workflows/linux.yml)
[![Release](https://img.shields.io/github/v/release/katzenpost/katzenpost)](https://github.com/katzenpost/katzenpost/releases/latest)

The servers and client daemon of the [Katzenpost](https://katzenpost.network) post-quantum mix
network: the mix server, the directory authority, the courier and replica that carry
[Pigeonhole](https://katzenpost.network/docs/pigeonhole_explained/)'s asynchronous
communication, and `kpclientd`. The design is in the
[Echomix paper](https://arxiv.org/abs/2501.02933). Katzenpost is pre-alpha and has not been
audited.

![An application talks to kpclientd, which sends Sphinx packets through the gateway and the mix layers to a service node, whose courier relays Pigeonhole messages to the replicas. The directory authorities publish the PKI document that every node and client reads.](docs/architecture.svg)

## Use the mixnet

Applications such as [katzenqt](https://github.com/katzenpost/katzenqt) and
[hushphone](https://github.com/katzenpost/hushphone) connect to `kpclientd`. The
[latest release](https://github.com/katzenpost/katzenpost/releases/latest) has `kpclientd` debs
for Debian 13, Debian forky and Ubuntu 24.04 and 26.04, configured for namenlos, the public
network, and archives for Linux, macOS and Windows:

```sh
curl -LO https://github.com/katzenpost/katzenpost/releases/latest/download/kpclientd_debian-13_amd64.deb
sudo apt install ./kpclientd_debian-13_amd64.deb
systemctl --user enable --now kpclientd
```

Or build it from source:

```sh
make kpclientd
mkdir -p "$XDG_RUNTIME_DIR/katzenpost"
cmd/kpclientd/kpclientd -c docker/client-configs/namenlos.toml
```

To write an application, use [thin_client](https://github.com/katzenpost/thin_client).

## Run a network

The `katzenpost` deb installs the servers and tools, with `kpserver@`, `kpauthority@` and
`kpreplica@` as systemd template units, shipped disabled. See the
[admin guide](https://katzenpost.network/docs/admin_guide/), [kno](https://github.com/katzenpost/kno),
which builds and checks a network, and [CONFIG_CHANGES.md](CONFIG_CHANGES.md) when you upgrade.
To run a test network on one machine with podman or docker:

```sh
make -C docker start wait run-ping
make -C docker stop
```

## Docs

- [Engineering Katzenpost](docs/ENGINEERING.md): building, testing, CI and releases, with a
  [repository tour](docs/repository-layout.md) and notes on the [cryptography](docs/cryptography.md)
- [Documentation](https://katzenpost.network/docs/), [specifications](https://katzenpost.network/docs/specs/),
  [threat model](https://katzenpost.network/research/Threat_Model_Doc.pdf) and
  [literature review](https://katzenpost.network/research/Literature_overview__website_version.pdf)
- [hpqc](https://github.com/katzenpost/hpqc), the cryptography library; [all repositories](https://github.com/katzenpost);
  [Zulip](https://katzenpost.zulipchat.com/)

## License

AGPL-3.0-only; see [LICENSE](LICENSE). [Donations](https://opencollective.com/the-katzenpost-software-project)
are welcome. Funded by the EU Horizon 2020 programme (grant No 653497, Panoramix), the Samsung
Next Stack Zero grant, and NLnet's [NGI0 PET](https://nlnet.nl/PET) (No 825310) and
[NGI Assure](https://nlnet.nl/assure) (No 957073) funds, with financial support from the
European Commission's Next Generation Internet programme.
