# Engineering Katzenpost

Back to the [README](../README.md).

This guide is for people changing the code in this repository. Application developers should
start with the [thin client documentation](https://katzenpost.network/docs/thin_client_howto/),
and operators with the [admin guide](https://katzenpost.network/docs/admin_guide/). Change this
guide in the same PR as the Makefile targets, workflows or packaging it describes.

## Building

You need Go at the version in the `go` line of [go.mod](../go.mod), make, and a C compiler for
cgo. On Debian or Ubuntu, `sudo apt-get install build-essential`.

```sh
make all          # every binary, each in its cmd/<name>/ directory
make kpclientd    # or any one of them: server, dirauth, courier, replica, ...
make clean
```

`make all` builds server, dirauth, genconfig, ping, motd, courier, replica, echo-plugin, fetch,
genkeypair, geometry, http-proxy-client, http-proxy-server, kpclientd, voucher-router,
service-directory and sphinx. Binaries get their version from `git describe --tags`. CI builds
and tests on Linux (`linux.yml`), macOS (`darwin.yml`) and Windows with MSYS2
(`windows-msys-64bit-gcc-ucrt-msvcrt-golang-test.yml`).

The website's [Build from source](https://katzenpost.network/docs/build_from_source/) page pins
the versions of katzenpost, hpqc, thin_client and katzenqt that work together.

## Repository layout

See [cryptography.md](cryptography.md) for the protocols and the schemes they can use.

## Generated code

The Pigeonhole messages in `pigeonhole/pigeonhole_messages.trunnel` are compiled to Go with the
Katzenpost fork of [trunnel](https://github.com/katzenpost/trunnel). `go generate` runs a build
driver that calls a `trunnel` binary, which must be on your `$PATH`:

```sh
go install github.com/katzenpost/trunnel/cmd/trunnel@latest
(cd pigeonhole && go generate ./...)
```

This rewrites `pigeonhole/trunnel_messages.go`. Never edit that file by hand: edit the schema and
regenerate. If you change the schema, also update the padding assumptions in
`pigeonhole/geo/geometry.go` and run the padding tests in `pigeonhole/`.

## Testing

Unit tests:

```sh
make test-unit                 # authority, client, core, server, courier, pigeonhole, pigeonservice
make test-replica
make test-suite suite=core     # one suite, as CI runs it
make check                     # go vet and govulncheck
```

Both test targets first run `make test-config`, which generates the docker network's
configuration, because some tests read it.

The docker test network runs a whole mixnet on one machine, with podman or docker. It is the
most complete example of how to configure a network:

```sh
cd docker
make start wait run-ping       # start, wait for consensus, send a ping
make test                      # the integration tests; make test-short runs them with -short
make stop
make help                      # every target
```

[docker/README.rst](../docker/README.rst) covers the rest: ports, transports (TCP and QUIC),
distros, parallel networks, metrics, network chaos with pumba, build caches and cleaning up.

Other tests:

- Cross-version interop: `make interop` and `make interop-matrix` run the network with some nodes
  on released tags; `make -C docker interop-gate` takes `release_refs`. See section 12 of
  [docker/README.rst](../docker/README.rst).
- namenlos: `make check-live` (`make -C docker client-check`) runs the working-tree client
  against the public network, using only the public `docker/client-configs/namenlos.toml`. Do
  not point servers, authorities or replicas at namenlos.
- Fuzzing: [fuzz/README.md](../fuzz/README.md).
- TLA+ models: `make tla`. Each model has its README: [client](../client/tla/README.md),
  [server](../server/tla/README.md) and [voting authority](../authority/voting/tla/README.md).
- Benchmarks: `make bench` runs `bench-sphinx`, `bench-handshake` and `bench-replica`.
- CI on your machine: `make ci-local` runs the workflows with act, forgejo-runner or
  woodpecker-cli in the CI image; `make ci-native` runs the same suites directly on the host.

## CI and the merge queue

PRs merge through a merge queue. These workflows run on a pull request and again on
`merge_group`:

- `linux.yml`, `darwin.yml`, `windows-msys-64bit-gcc-ucrt-msvcrt-golang-test.yml` and
  `replica-tests.yml`: unit tests;
- `deb.yml`: the Debian packages, and `make check-version`;
- `docker-interop-gate.yml`: the cross-version check, when the PR has the `interop` label or
  `[interop]` in its title, body or head commit message. The required check passes when every
  job that ran passes.

`docker-mixnet.yml` runs the docker integration tests in the merge queue, on pushes and on a
schedule. `tla.yml` and `docker-quic.yml` run on pull requests and on a schedule. These run
only on a schedule or by hand: `namenlos-client-check.yml` (every six hours, so a PR never waits
on the public network), `interop-releases.yml` (the two newest tags), `govulncheck.yml`,
`benchmarks-sphinx.yml` and `benchmarks-daily.yml`. The same suites are mirrored for Forgejo
(`.forgejo/workflows/`) and Woodpecker (`.woodpecker/`); `make ci-config-check` fails if a suite
is missing from one of them.

## Packaging and releases

There are two Debian packages:

- `kpclientd`, for users: the client daemon, its `kpclientd.toml` and `thinclient.toml`
  configured for namenlos, and its systemd system and user units;
- `katzenpost`, for operators: every other binary with a `kp` prefix, with kpserver,
  kpauthority and kpreplica as systemd template units, shipped disabled.

A release is a `vX.Y.Z` tag on `main` whose commit has `X.Y.Z` at the top of
`debian/changelog`. Pushing the tag publishes a GitHub release with debs for Debian 13, Debian
forky, Ubuntu 24.04 and Ubuntu 26.04, kpclientd archives for Linux (amd64, arm64), macOS (arm64)
and Windows (amd64), and `SHA256SUMS`. [RELEASING.md](../RELEASING.md) has the steps.

```sh
make deb                       # build the debs in a container
make check-version tag=vX.Y.Z  # check the changelog against a tag
```

## Configuration changes

A change to any component's configuration adds an entry to
[CONFIG_CHANGES.md](../CONFIG_CHANGES.md), marked **[breaking]** if an operator must act.
Configuration loaders ignore unknown keys, so that an upgrade never stops a node over a stray
line; `--validate-only` and `kpconfig` use `common/tomlstrict` to report them.

## Conventions

- Each Go file starts with `// SPDX-License-Identifier: AGPL-3.0-only`.
- Log through `core/log`. Long-lived goroutines use `core/worker` and stop on `HaltCh`.
- Commit messages are short: a prefix naming the area, then what changed, such as
  `replica: stream stored boxes to the bridge`.
- One change per PR.

## Pull requests and issues

Write `Fixes #N` in the PR body for each issue the PR resolves, so that merging closes it.
Review comes first, then the merge queue.

## Debugging and profiling

The mix server, directory authority and kpclientd can send pprof profiles to a
[Pyroscope](https://grafana.com/docs/pyroscope/latest/get-started/) server when built with the
`pyroscope` build tag:

```sh
(cd cmd/server && go build -tags pyroscope)
export PYROSCOPE_SERVER_ADDRESS=http://localhost:4040
export PYROSCOPE_APP_NAME=katzenpost_mix_server
export PYROSCOPE_SERVICE_TAG=mix1
cmd/server/server -f katzenpost-server.toml
```

The docker network can run Prometheus and Grafana with `make start-with-client-metrics`; see
section 5 of [docker/README.rst](../docker/README.rst).

## Future roadmap

### Software development

To be written.

### Theoretical research

To be written.
