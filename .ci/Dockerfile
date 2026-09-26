# SPDX-License-Identifier: AGPL-3.0-only

FROM docker.io/catthehacker/ubuntu:act-22.04

ARG ACT_VERSION=0.2.89
ARG FORGEJO_RUNNER_VERSION=6.3.1

RUN curl -fsSL "https://github.com/nektos/act/releases/download/v${ACT_VERSION}/act_Linux_x86_64.tar.gz" \
      | tar -xz -C /usr/local/bin act \
 && curl -fsSL -o /usr/local/bin/forgejo-runner \
      "https://code.forgejo.org/forgejo/runner/releases/download/v${FORGEJO_RUNNER_VERSION}/forgejo-runner-${FORGEJO_RUNNER_VERSION}-linux-amd64" \
 && chmod +x /usr/local/bin/act /usr/local/bin/forgejo-runner
