# Katzenpost Mix Network Scratch Library

This library is provided for making an ephemeral capability-based
storage system for Katzenpost, so that clients may exchange capabilities to
read and write storage locations in order to establish asynchronous end-to-end
communication channels.

It consists of a Katzenpost Kaetzchen plugin service and a corresponding
client library that can be used to read and write data to this service.

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
git clone https://github.com/katzenpost/katzenpost cd katzenpost/docker && make start wait
```

You can then run the end-to-end tests like so:

```bash
  cd ../katzenpost/scratch && make dockerdockertest
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
