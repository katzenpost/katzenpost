# SPDX-License-Identifier: AGPL-3.0-only

FROM ghcr.io/astral-sh/uv:python3.12-trixie AS uv
FROM docker.io/library/golang:1.26 AS go
FROM docker.io/library/rust:1-trixie AS rust

FROM docker.io/catthehacker/ubuntu:act-22.04

ARG ACT_VERSION=0.2.89
ARG ACT_SHA256=0191d6f1f3b716b5c55820032605d05fc3c1cdbf581ebeff655019e5dd1524c0
ARG FORGEJO_RUNNER_VERSION=13.2.0
ARG FORGEJO_RUNNER_SHA256=fadaec897f5e6641c363f87ecaf75f866f99c81b7097ec6b433e4c48123fcad1
ARG WOODPECKER_CLI_VERSION=3.18.1
ARG WOODPECKER_CLI_SHA256=e7e78b0cc2f1172407d4e1439909bf8f55fb9b55f0fa79ae28338b195ecb56a5

COPY --from=uv /usr/local/bin/uv /usr/local/bin/uv
COPY --from=uv /usr/local/bin/uvx /usr/local/bin/uvx
COPY --from=go /usr/local/go /usr/local/go
COPY --from=rust /usr/local/rustup /usr/local/rustup
COPY --from=rust /usr/local/cargo /usr/local/cargo

ENV GOROOT=/usr/local/go
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/go/bin:/usr/local/cargo/bin:${PATH}

WORKDIR /tmp/runners

RUN curl -fsSLO "https://github.com/nektos/act/releases/download/v${ACT_VERSION}/act_Linux_x86_64.tar.gz" \
 && echo "${ACT_SHA256}  act_Linux_x86_64.tar.gz" | sha256sum -c - \
 && tar -xzf act_Linux_x86_64.tar.gz act \
 && install -m 0755 act /usr/local/bin/act \
 && curl -fsSLO "https://code.forgejo.org/forgejo/runner/releases/download/v${FORGEJO_RUNNER_VERSION}/forgejo-runner-${FORGEJO_RUNNER_VERSION}-linux-amd64" \
 && echo "${FORGEJO_RUNNER_SHA256}  forgejo-runner-${FORGEJO_RUNNER_VERSION}-linux-amd64" | sha256sum -c - \
 && install -m 0755 "forgejo-runner-${FORGEJO_RUNNER_VERSION}-linux-amd64" /usr/local/bin/forgejo-runner \
 && curl -fsSLO "https://github.com/woodpecker-ci/woodpecker/releases/download/v${WOODPECKER_CLI_VERSION}/woodpecker-cli_linux_amd64.tar.gz" \
 && echo "${WOODPECKER_CLI_SHA256}  woodpecker-cli_linux_amd64.tar.gz" | sha256sum -c - \
 && tar -xzf woodpecker-cli_linux_amd64.tar.gz woodpecker-cli \
 && install -m 0755 woodpecker-cli /usr/local/bin/woodpecker-cli \
 && cd / && rm -rf /tmp/runners

WORKDIR /

RUN rustup component add clippy

RUN go version && uv --version && cargo clippy --version && act --version \
 && forgejo-runner --version && woodpecker-cli --version
