# Katzenpost Mix Network ScatterStream Library

This library is provided for establishing reliable bidirectional communication channel between a pair of clients using a shared secret. From the shared secret, sequences of message storage addresses (32 bytes) and symmetric message encryption keys are derived. Each client runs a protocol state machine that fetches and acknowleges frames of data, and re-transmits unacknowledged frames in order to provide a reliable channel over a lossy storage service. Storage addresses are mapped to nodes published in Katzenpost's Directory Authority system, which runs a service called "Map" that provides a simple lossy storage service where content is limited to a configurable buffer size and automatically expire.

In Katzenpost, the Directory Authority system publishes a PKI document that contains the set of map services and clients deterministically select a storage service instance for each message they send to the network.

## unit tests

Unit tests are run using go test:

```bash
go test -v ./...
```

## GitHub CI tests

End-to-End tests are run using dockerized instances of the Katzenpost mixnet.

To start a locally running testnet, navigate to the docker directory of this
repository and follow the README.rst to familiarize yourself with starting and
stopping a local mixnet using the make commands.

Once you have a mixnet running, e.g.:

```bash
git clone https://github.com/katzenpost/katzenpost -b add_reliable_streams && cd katzenpost/docker && make start wait
```

You can then run the end-to-end tests like so:

```bash
  cd ../katzenpost/stream && make dockerdockertest
```

# License

AGPLv3

# Donations

Your donations are welcomed and can be made through Open Collective [here.](https://opencollective.com/the-katzenpost-software-project)

# Supported By

[![NGI](https://katzenpost.mixnetworks.org/_static/images/eu-flag-tiny.jpg)](https://www.ngi.eu/about/)
<a href="https://nlnet.nl"><img src="https://nlnet.nl/logo/banner.svg" width="160" alt="NLnet Foundation"/></a>
<a href="https://nlnet.nl/assure"><img src="https://nlnet.nl/image/logos/NGIAssure_tag.svg" width="160" alt="NGI Assure"/></a>

This project has received funding from:

* NGI Assure Fund, a fund established by NLnet with financial support from the European Commission's Next Generation Internet programme, under the aegis of DG Communications Networks, Content and Technology under grant agreement No 957073.
