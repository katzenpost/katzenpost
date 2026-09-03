.PHONY: clean clean-local clean-local-dryrun stop-all clean-testnets clean-image-% clean-container-% clean-images test test-distros test-distro-% rootshell shell run-ping go-mod-tidy go-mod-upgrade help install-git-hooks disable-git-hooks start stop client-restart clean-client client-logs courier-restart servicenode1-restart replica-restart replica-test config-only watch-replicas watch-auth watch-mixes watch-courier watch-servicenode watch-gateway watch-all-separate start-with-client-metrics print-url-grafana print-url-prometheus pumba-latency pumba-loss pumba-corrupt pumba-pause pumba-status pumba-stop selfcheck-cache-restore thin-client-sync pigeonhole-cp-genkey pigeonhole-cp-roundtrip check-ports interop-build interop-build-previous interop-build-current interop-build-candidate interop-image-check interop-compose interop-selfcheck-cache-restore interop-start interop-wait interop-run-ping interop-http-check interop-check interop-check-role interop-smoke interop-client-check interop-activate interop-record-artifact interop-swap-mix interop-swap-gateway interop-swap-servicenode interop-swap-dirauth interop-swap-replica interop-swap-courier interop-swap-http interop-swap-client2 interop-restore-role interop-noop interop-test interop-report interop-validate interop-test-baseline interop-test-role interop-test-mixed-network interop-test-quorums interop-stop interop-clean interop-clean-dryrun interop-clean-cache interop-clean-results interop-clean-image interop-clean-all

help:
	@echo "These make targets allow you to control the test network:"
	@echo " config-only               - generate configuration files only (no docker containers)"
	@echo " start                     - start the testnet"
	@echo " stop                      - stop the testnet"
	@echo " client-restart            - restart just the kpclientd daemon"
	@echo " client-logs               - view kpclientd daemon logs"
	@echo " courier-restart           - restart courier plugin via thwack interface"
	@echo " servicenode1-restart      - restart servicenode container"
	@echo " replica-restart           - rebuild replica binary and restart all replica containers"
	@echo " wait                      - wait until every node reports ready against the current consensus"
	@echo " watch                     - tail -F all logs"
	@echo " watch-replicas            - monitor all replica logs"
	@echo " watch-auth                - monitor all directory authority logs"
	@echo " watch-mixes               - monitor all mix node logs"
	@echo " watch-courier             - monitor courier service log"
	@echo " watch-servicenode         - monitor service node log"
	@echo " watch-gateway             - monitor gateway log"
	@echo " watch-all-separate        - monitor all logs with component labels"
	@echo " start-with-client-metrics - start with prometheus + grafana and kpclientd metrics"
	@echo " print-url-grafana         - print the Grafana URL"
	@echo " print-url-prometheus      - print the Prometheus URL"
	@echo " pumba-latency             - induce network delay/jitter on mixnet containers (see pumba_* vars)"
	@echo " pumba-loss                - induce packet loss on mixnet containers (see pumba_* vars)"
	@echo " pumba-corrupt             - induce single-bit packet corruption (see pumba_corrupt_pct)"
	@echo " pumba-pause               - freeze a single container for pumba_pause_duration"
	@echo " pumba-status              - show all running pumba chaos containers"
	@echo " pumba-stop                - stop every katzenpost_pumba_* chaos container"
	@echo " status                    - show testnet consensus status"
	@echo " show-latest-vote          - does what it says"
	@echo " thin-client-sync          - clone/update docker/thin_client at thin_client_ref"
	@echo " pigeonhole-cp-genkey      - print a fresh pigeonhole channel keypair"
	@echo " pigeonhole-cp-roundtrip   - round-trip a file through a pigeonhole channel"
	@echo " run-ping                  - send a ping over the testnet"
	@echo " test                      - run every component's docker integration tests (requires the testnet to be up)"
	@echo " clean-bin                 - stop, and delete compiled binaries"
	@echo " clean-local               - stop the current network, and wipe its state (keeps the build cache)"
	@echo " clean-local-dryrun        - show what clean-local would delete"
	@echo " stop-all                  - stop every network, one per distro inferred from build stamps"
	@echo " clean                     - stop all networks, wipe all state, plus base images and the build cache"
	@echo " test-distros              - bring up and ping the testnet on every DISTRO, leaving them running (serial, or parallel with make -j)"
	@echo

install-git-hooks:
	git -C .. config core.hooksPath .githooks

disable-git-hooks:
	@git -C .. config --unset-all core.hooksPath 2>/dev/null || true

warped?=true
no_decoy?=true
no_client_decoy?=false
no_courier_replica_decoy?=false
no_mixdecoy?=true
no_gatewaydecoy?=true
no_metrics?=true
pyroscope_dirauth?=false
pyroscope_kpclientd?=false
kpclientd_metrics?=false
epoch_duration?=2m
# session_grace_period sets how long kpclientd preserves per-app
# state after a thin-client connection drops without thin_close.
# Thirty seconds is the docker-mixnet default: short enough that
# a SIGKILL'd test subprocess's resources are visibly reaped
# within a single CI epoch, long enough that a same-test reconnect
# resumes seamlessly. Override on the make command line for
# longer test scenarios. Empty means "use the daemon's compile-time
# default" (currently 10 minutes).
session_grace_period?=30s
mixes=3
auths=3
gateways=1
serviceNodes=3
storageNodes=5

# number of pings sent by run-ping target
npings?=10

# Parameters. Sampling safety caps for each rate are derived inside the
# library (common.SafetyCap) from the rate itself, so no MaxDelay knobs
# are passed to genconfig.
mu=0.005
lP=0.001
lL=0.0005
lM=0.0005
lR=0.005

UserForwardPayloadLength=2000

# Mix node scheduler tuning (0 = use defaults)
schedulerSlack=0
schedulerMaxBurst=0
sendSlack=0
unwrapDelay=0
numSphinxWorkers=0

# hybrid ctidh PQ can work here, but requires manually building ctidh.
nike=x25519

# kem can be Kyber1024-X448 or any of the other schemes at https://github.com/cloudflare/circl/blob/main/kem/schemes/schemes.go (and then nike must be unset)
kem=

DISTROS=alpine debian-trixie ubuntu-26.04
distro=alpine

# Distro strings are "<family>" (alpine) or "<family>-<version>" (e.g.
# debian-trixie, ubuntu-25.10). The base image is derived uniformly:
# alpine -> alpine_base_image?=, any debian-<tag> -> docker.io/debian:<tag>,
# any ubuntu-<tag> -> docker.io/ubuntu:<tag>. Adding a new version is
# purely a new FROM tag: `make distro=ubuntu-26.04 start wait` just works.
distro_family=$(firstword $(subst -, ,$(distro)))
distro_version=$(patsubst $(distro_family)-%,%,$(distro))
ifeq ($(distro_family),alpine)
  base_dockerfile=Dockerfile.base.alpine
  alpine_base_image?=docker.io/alpine:3.21
  distro_base_image=$(alpine_base_image)
else
  base_dockerfile=Dockerfile.base.apt
  distro_base_image=docker.io/$(distro_family):$(distro_version)
endif
# Universal escape hatch: make base_image=my/registry:tag start wait
base_image?=$(distro_base_image)
# Single source of truth for the Go toolchain: the go directive in the
# repo's go.mod. The base Dockerfiles keep the same value as an ARG
# default only so `podman build` works standalone.
GO_VERSION?=$(shell grep '^go ' ../go.mod | cut -d' ' -f2)
wirekem=xwing
# Network directory under docker/. Defaults to the current distro's network
# (e.g. mixnet-alpine), so `make distro=foo start` targets mixnet-foo just
# like the test-distros legs. A custom net_name= still overrides it.
net_name=mixnet-$(distro)
# docker-compose normalizes the project name (directory name) by stripping
# dots; compute the actual network name the same way so --network= matches
# the bridge compose creates.  Only the wait target uses this (fetch
# --require-ready probes per-node metrics endpoints via container DNS).
compose_network_name = $(subst .,,$(net_name))_katzenpost-net
# Deterministic base_port derived from the network name + a per-checkout
# random seed so parallel checkouts on the same machine get different
# ports even with the same net_name.  Override with base_port=<n>.
base_port?=$(shell [ -f .base_port_seed ] || dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64 | head -c 32 > .base_port_seed; printf '%s%s' '$(net_name)' "$$(cat .base_port_seed)" | cksum | awk '{printf "%d", 30000 + ($$1 % 20000)}')
bind_addr=127.0.0.1
docker_compose_yml=$(net_name)/docker-compose.yml
# bash is installed in every base image (alpine, debian, ubuntu), so a
# single shell covers all distros.
sh?=bash
cache_dir=cache
# The go module cache (source content, read-only) is shared across distros.
# The go build cache holds compiled archives that are sensitive to the C
# library (musl vs glibc, and glibc versions), and Go's cache key does not
# capture that, so the build cache is scoped per distro.
go_mod_cache=$(cache_dir)/go
go_build_cache=$(cache_dir)/go-build-$(distro)

# The two most recent release tags that do NOT link rocksdb (grocksdb was
# dropped at v0.0.99). Older rocksdb-era releases cannot be built in the
# rocksdb-free base image, so they are skipped; until a second non-rocksdb
# release exists this yields a single ref and the suite runs candidate vs
# current only. The scan is bounded to the newest tags to stay cheap.
interop_release_refs=$(shell git tag --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$$' | head -25 | while read t; do git show "$$t:go.mod" 2>/dev/null | grep -qi grocksdb || echo "$$t"; done | head -2)
current_ref?=$(word 1,$(interop_release_refs))
previous_ref?=$(word 2,$(interop_release_refs))
candidate_ref?=HEAD
BASELINE?=current
COMPONENT_VERSION?=candidate
SWAP_RUNNING?=true
CHECK_CLIENT_VERSION?=$(BASELINE)
CHECK_HTTP_VERSION?=$(BASELINE)
FETCH_VERSION?=$(BASELINE)
interop_dir=$(cache_dir)/interop/$(distro)
# previous is included only when a second non-rocksdb release exists; with
# just one, the suite runs candidate vs current and skips previous/quorums.
interop_versions=candidate current $(if $(strip $(previous_ref)),previous)
interop_network_versions=current $(if $(strip $(previous_ref)),previous)
interop_roles=mix gateway servicenode dirauth replica courier http client2
interop_services_mix=$(addprefix mix,$(shell seq $(mixes)))
interop_services_gateway=$(addprefix gateway,$(shell seq $(gateways)))
interop_services_servicenode=$(addprefix servicenode,$(shell seq $(serviceNodes)))
interop_services_dirauth=$(addprefix auth,$(shell seq $(auths)))
interop_services_replica=$(addprefix replica,$(shell seq $(storageNodes)))
interop_services_courier=$(interop_services_servicenode)
interop_services_http=$(interop_services_servicenode)
interop_services_client2=kpclientd
# service:binary pairs for the compose command rewrite, derived from the
# topology so adding mixes, gateways, service nodes, dirauths or replicas
# needs no edit here. Courier and proxy_server share the servicenode
# containers and are rewritten from their own toml, not here.
interop_compose_bins=\
  $(addsuffix :server,$(interop_services_mix) $(interop_services_gateway) $(interop_services_servicenode)) \
  $(addsuffix :replica,$(interop_services_replica)) \
  $(addsuffix :dirauth,$(interop_services_dirauth))
interop_runtime_bins=server dirauth replica courier kpclientd proxy_server proxy_client
interop_probe_bins=fetch ping
interop_build_bins=$(interop_runtime_bins) $(interop_probe_bins) genconfig client_tests
interop_check_target?=interop-check
interop_base_image?=katzenpost-$(distro)_base
# The interop recipes run in the katzenpost base image directly; it already
# ships the Go toolchain plus the bash, perl and curl they need, so there is
# no separate interop image to build, stamp, save or load.
interop_image=$(interop_base_image)
interop_net_name?=interop-$(distro)
interop_report_dir?=interop-results
interop_submake=$(MAKE)
interop_stop_make=$(MAKE)
interop_heartbeat?=5
interop_epoch_duration?=30s
interop_initial_leg_seconds?=600
interop_ping_timeout?=3m
interop_ping_attempts?=3
interop_readiness_timeout?=5m
interop_fetch_timeout?=30s
interop_consensus_timeout?=720
interop_leg_timeout?=45m
DEBUG?=0
INTEROP_PINGS?=$(npings)

# thin_client / pigeonhole-cp (rust). thin-client-sync clones the
# pinned ref into docker/thin_client; thin_client_dir?= overrides that with
# an existing checkout (devs, and thin_client's own CI, which must build
# the exact code under test rather than a re-clone). The rust build image
# is built FROM the per-distro base image so binary and runtime share a C
# library; the cargo home and target dirs are cached per distro the same
# way the go build cache is.
thin_client_ref?=0.0.23
thin_client_dir?=thin_client
thin_client_mount=-v $(shell readlink -f $(thin_client_dir)):/go/thin_client:ro
cargo_home=$(cache_dir)/cargo-home-$(distro)
cargo_target=$(cache_dir)/cargo-target-$(distro)
roundtrip_size?=65536

# genconfig_args is shared by the docker-compose generation inside the
# base image and the host-side config-only target. Bools and tunables
# are always passed with explicit values so the operator's intent is
# never swallowed by a cobra default; 0/empty means "library default"
# (e.g. --schedulerSlack 0, --sessionGracePeriod 0). The `=` assignment
# (not `:=`) keeps command-line overrides (make mixes=10 gateways=2 ...)
# flowing through to this expansion.
#
# no_decoy is a master toggle covering clients, couriers, and replicas.
# no_client_decoy and no_courier_replica_decoy allow selective disabling
# when no_decoy=false. no_mixdecoy controls mix node decoys
# independently. The presence flags below are emitted only when true
# (their cobra defaults are false); --noMixDecoy/--noGatewayDecoy
# default true in cobra, so they are always passed explicitly.
ifeq ($(no_decoy),true)
  noDecoyFlag=--noDecoy
endif

ifeq ($(no_client_decoy),true)
  noClientDecoyFlag=--noClientDecoy
endif

ifeq ($(no_courier_replica_decoy),true)
  noCourierReplicaDecoyFlag=--noCourierReplicaDecoy
endif

ifeq ($(no_metrics),true)
  noMetricsFlag=--noMetrics
endif

# Mix key persistence across clean restarts. The testnet's dirauth
# consensus survives `make stop`/`make start` because node dirs are
# bind-mounted onto the host; persist the mix keys to each node's DataDir
# on clean shutdown and reload them on the next boot so a restart doesn't
# leave the fresh keys mismatched with the retained consensus (surfaces
# as first-hop MAC failures until the next epoch). Always passed with an
# explicit value; empty disables persistence in generated configs.
persistMixKeysOnShutdownDir ?= mixkeys
ifeq ($(pyroscope_dirauth),true)
  pyroscope_dirauth_tags=-tags pyroscope
  pyroscopeDirauthFlag=--pyroscopeDirauth
endif

ifeq ($(pyroscope_kpclientd),true)
  pyroscope_kpclientd_tags=pyroscope
  pyroscopeKpclientdFlag=--pyroscopeKpclientd
endif

ifeq ($(kpclientd_metrics),true)
  kpclientd_metrics_tags=kpclientd_metrics
  # The --kpclientdMetricsAddress flag gates enablement only; genconfig
  # derives the listener port from base_port (base_port+2004) so it stays
  # in lockstep with the prometheus scrape target. The port passed here is
  # documented for clarity but ignored.
  kpclientdMetricsFlag=--kpclientdMetricsAddress 127.0.0.1:$(shell expr $(base_port) + 2004)
endif

# Combine kpclientd build tags. Two `-tags ...` invocations on a single go
# build line do not compose; the second wins. Build one quoted list instead.
kpclientd_build_tags=$(strip $(pyroscope_kpclientd_tags) $(kpclientd_metrics_tags))
ifneq ($(kpclientd_build_tags),)
  kpclientd_tags_flag=-tags "$(kpclientd_build_tags)"
endif

genconfig_args= --wirekem $(wirekem) --addr $(bind_addr) --nrVoting $(auths) --nodes $(mixes) \
	--gateways $(gateways) --serviceNodes $(serviceNodes) --storageNodes $(storageNodes) \
	--mu $(mu) --lambdaP $(lP) --lambdaL $(lL) --lambdaM $(lM) --lambdaR $(lR) \
	--nike "$(nike)" --kem "$(kem)" \
	--noMixDecoy=$(no_mixdecoy) --noGatewayDecoy=$(no_gatewaydecoy) \
	$(noDecoyFlag) $(noClientDecoyFlag) $(noCourierReplicaDecoyFlag) $(noMetricsFlag) \
	--epochDuration "$(epoch_duration)" --sessionGracePeriod $(or $(session_grace_period),0) \
	$(pyroscopeDirauthFlag) $(pyroscopeKpclientdFlag) $(kpclientdMetricsFlag) \
	--schedulerSlack $(schedulerSlack) --schedulerMaxBurst $(schedulerMaxBurst) \
	--sendSlack $(sendSlack) --unwrapDelay $(unwrapDelay) --numSphinxWorkers $(numSphinxWorkers) \
	--persistMixKeysOnShutdownDir "$(persistMixKeysOnShutdownDir)" \
	--UserForwardPayloadLength $(UserForwardPayloadLength) --logLevel $(log_level)

interop_genconfig_args=--wirekem $(wirekem) --addr $(bind_addr) --nrVoting $(auths) --nodes $(mixes) \
	--gateways $(gateways) --serviceNodes $(serviceNodes) --storageNodes $(storageNodes) \
	--nike "$(nike)" --kem "$(kem)" --noMixDecoy=$(no_mixdecoy) \
	--noGatewayDecoy=$(no_gatewaydecoy) --noDecoy --noMetrics --epochDuration "$(interop_epoch_duration)" \
	--UserForwardPayloadLength $(UserForwardPayloadLength) --logLevel $(log_level)

# Pumba network chaos. Off by default; invoke `make pumba-latency` or
# `make pumba-loss` to start a sidecar that applies `tc netem` qdiscs in
# each target container's net namespace, and `make pumba-stop` to remove
# it. Pumba speaks the docker API over the socket; on a podman host the
# rootless socket at $XDG_RUNTIME_DIR/podman/podman.sock is mounted in
# its place. The default target regex matches every katzenpost service
# whose container_name follows the predictable `<role><n>` pattern set
# by genconfig: gateway, servicenode, mix, replica, and kpclientd. The
# dirauths, prometheus, grafana, and pyroscope are deliberately excluded
# from chaos by default.
#
# The default delay and jitter are calibrated against observations on
# the live Namenlos mixnet (https://status.namenlos.network), where
# inter-component ICMP round-trip times cluster around 13-30 ms with
# outliers up to 133 ms for geographically distant peers. We pick a
# one-way per-container egress delay of 25 ms with 10 ms jitter so a
# nine-hop ping accumulates roughly the same end-to-end network
# latency observers see on the real network, before mix sampling
# delays are layered on top.
#
#   pumba_latency_ms      one-way per-container egress delay, in ms (default 25)
#   pumba_jitter_ms       jitter in milliseconds (default 10)
#   pumba_distribution    uniform, normal, pareto, paretonormal (default normal)
#   pumba_correlation_pct optional jitter correlation, percent (default empty)
#   pumba_loss_pct        packet loss percent for `pumba-loss` (default 5)
#   pumba_loss_corr_pct   optional loss correlation, percent (default empty)
#   pumba_corrupt_pct     bit-corruption percent for `pumba-corrupt` (default 0.01)
#   pumba_pause_duration  duration of `pumba-pause` freeze (default 30s)
#   pumba_pause_target    container name to pause (default replica1)
#   pumba_duration        how long to apply netem chaos (default 1h)
#   pumba_targets         pumba target spec; default re2 regex matches
#                         every mix/gateway/servicenode/replica/kpclientd
#                         container of the current network. genconfig no
#                         longer sets container_name, so compose names the
#                         containers <net_name>-<service>-<n>; the regex
#                         anchors on the project prefix to avoid touching
#                         parallel networks. Override with a narrower
#                         regex or a space-separated list.
#   pumba_container       name of the chaos container. Override per lane
#                         (e.g. katzenpost_pumba_slowreplica) when
#                         stacking asymmetric chaos; `pumba-stop` removes
#                         every container whose name starts with
#                         `katzenpost_pumba_`.
pumba_latency_ms?=25
pumba_jitter_ms?=10
pumba_distribution?=normal
pumba_correlation_pct?=
pumba_loss_pct?=5
pumba_loss_corr_pct?=
pumba_corrupt_pct?=0.01
pumba_pause_duration?=30s
pumba_pause_target?=$(net_name)-replica1-1
pumba_duration?=1h
pumba_targets?=re2:^$(net_name)-(mix[0-9]+|gateway[0-9]+|servicenode[0-9]+|replica[0-9]+|kpclientd)-[0-9]+$$
pumba_image?=docker.io/gaiaadm/pumba:latest
pumba_tc_image?=docker.io/gaiadocker/iproute2
pumba_container?=katzenpost_pumba_chaos
pumba_prefix=katzenpost_pumba_

ifeq ($(docker),podman)
  pumba_sock_mount=-v $$XDG_RUNTIME_DIR/podman/podman.sock:/var/run/docker.sock
else
  pumba_sock_mount=-v /var/run/docker.sock:/var/run/docker.sock
endif

ifneq ($(pumba_correlation_pct),)
  pumba_correlation_flag=--correlation $(pumba_correlation_pct)
endif

ifneq ($(pumba_loss_corr_pct),)
  pumba_loss_corr_flag=--correlation $(pumba_loss_corr_pct)
endif

# log_level can be DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL
log_level=DEBUG

# Runtime backend. Defaults to podman when it is on PATH, so `docker` is
# only used when explicitly requested (make docker=docker ...).
docker?=$(shell command -v podman >/dev/null 2>&1 && echo podman || echo docker)

ldflags="-extldflags '-Wl,-z,stack-size=0x1F40000' -buildid= -X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped}"

uid?=$(shell [ "$$SUDO_UID" != "" ] && echo "$$SUDO_UID" || id -u)
gid?=$(shell [ "$$SUDO_GID" != "" ] && echo "$$SUDO_GID" || id -g)

ifeq ($(docker),podman)
  # Rootless podman maps container uid 0 to the invoking user, so build
  # and compose artifacts stay user-owned and host `rm -rf`/`git clean`
  # can delete them directly (see the `clean`/`clean-local` targets).
  docker_user=0:0
  replace_name= --replace --name
  i_if_podman= -i
else
  # Rootful docker: run build containers as the invoking user so cache
  # files are not left root-owned.
  docker_user=$(uid):$(gid)
  replace_name= --name
  i_if_podman=
endif
docker_args=--user ${docker_user} --volume $(shell readlink -f ..):/go/katzenpost --workdir /go/katzenpost \
	-v $(shell readlink -f .)/$(go_mod_cache):/go/ \
	-v $(shell readlink -f .)/$(go_build_cache):/gocache/ \
	-e GOCACHE=/gocache -e GOPATH=/go --pids-limit 4096

mount_net_name=-v `pwd`/$(net_name):/$(net_name)

docker_compose_v1_or_v2?= $(shell [ -e /usr/libexec/docker/cli-plugins/docker-compose ] && echo /usr/libexec/docker/cli-plugins/docker-compose || echo docker-compose)
ifeq ($(docker),podman)
  docker_compose= DOCKER_USER=$(docker_user) DOCKER_HOST="unix://$$XDG_RUNTIME_DIR/podman/podman.sock" podman compose
else
  docker_compose= DOCKER_USER=$(docker_user) $(docker_compose_v1_or_v2)
endif

# Recursive `$(MAKE)` invocations inherit these instead of re-deriving
# them from a hardcoded argument list.
export docker docker_user docker_args distro sh warped net_name compose_network_name cache_dir mount_net_name
export no_decoy no_client_decoy no_courier_replica_decoy no_mixdecoy no_gatewaydecoy
export no_metrics pyroscope_dirauth pyroscope_kpclientd kpclientd_metrics
export wirekem nike kem mixes auths gateways serviceNodes storageNodes
export mu lP lL lM lR UserForwardPayloadLength log_level
export kpclientd_build_tags kpclientd_tags_flag pyroscope_dirauth_tags pyroscope_kpclientd_tags

docker_run_sh=$(docker) run ${docker_args} $(mount_net_name) --rm katzenpost-$(distro)_base $(sh) -c

testnet_binaries: $(net_name)/server.$(distro) $(net_name)/proxy_server.$(distro) $(net_name)/proxy_client.$(distro) $(net_name)/echo_server.$(distro) $(net_name)/dirauth.$(distro) $(net_name)/replica.$(distro) $(net_name)/courier.$(distro) $(net_name)/kpclientd.$(distro) $(net_name)/fetch.$(distro) | $(net_name) $(cache_dir)

$(net_name):
	mkdir -vp $(net_name)

$(cache_dir): $(cache_dir)/go $(go_build_cache) $(cargo_home) $(cargo_target)

$(cache_dir)/go:
	mkdir -vp $(cache_dir)/go

$(go_build_cache):
	mkdir -vp $(go_build_cache)

$(cargo_home):
	mkdir -vp $(cargo_home)

$(cargo_target):
	mkdir -vp $(cargo_target)

$(docker_compose_yml): ../cmd/genconfig/main.go $(distro)_base.stamp | $(net_name) $(cache_dir)
	$(docker) run ${docker_args} --rm katzenpost-$(distro)_base \
		$(sh) -c 'cd cmd/genconfig && go build && cd ../../docker \
		&& ../cmd/genconfig/genconfig $(genconfig_args) \
		--binSuffix .$(distro) --voting --outDir ./$(net_name) --baseDir /$(net_name) --port $(base_port) \
		--dockerImage katzenpost-$(distro)_base'

# Generate configuration files only (without docker containers)
# This is useful for tests that depend on config files existing (e.g., client/testdata symlinks)
config-only: | $(net_name)
	@echo "Generating mixnet configuration files without docker containers..."
	cd ../cmd/genconfig && go build && ./genconfig $(genconfig_args) \
		--voting --outDir ../../docker/$(net_name) --baseDir /$(net_name) --port $(base_port)
	@echo "Configuration files generated in ./$(net_name)/"
	@echo "Tests can now use the symlinked configs (e.g., client/testdata/client.toml -> ../../docker/$(net_name)/client/client.toml)"

$(net_name)/running.stamp:
	$(MAKE) start

# Restore committed self-check sidecars into each daemon's DataDir
# before docker compose up. The replica's CTIDH self-check costs
# multiple seconds per operation on a small CI runner, and Sphinx-
# side server self-checks all pile onto the same boot moment; the
# committed sidecars in ./selfcheck-cache/<svc>.toml short-circuit
# the live measurement on first boot. The daemon validates each
# loaded sidecar against the live host's NumCPU and the container's
# hostname (set by docker-compose to the service identifier, which
# matches the cache file's basename); a mismatch invalidates the
# cache and triggers a fresh measurement, which then overwrites
# the sidecar in the DataDir but never the committed copy here.
# A missing or topology-mismatched cache file is non-fatal; the
# daemon simply measures and writes its own.
selfcheck-cache-restore: $(docker_compose_yml)
	@if [ -d selfcheck-cache ]; then \
	  for f in selfcheck-cache/*.toml; do \
	    svc=$$(basename $$f .toml); \
	    if [ -d "$(net_name)/$$svc" ]; then \
	      cp "$$f" "$(net_name)/$$svc/selfcheck.toml"; \
	      echo "  restored $(net_name)/$$svc/selfcheck.toml from selfcheck-cache/$$svc.toml"; \
	    fi; \
	  done; \
	fi

check-ports:
	@for port in $$(seq $$(($(base_port) + 2000)) $$(($(base_port) + 2003))); do \
		if ss -tlnp "sport = :$$port" 2>/dev/null | grep -q LISTEN; then \
			echo "ERROR: port $$port is already in use (base_port=$(base_port))."; \
			echo "  Use 'make base_port=<N> start' or 'make stop' to free the ports."; \
			exit 1; \
		fi; \
	done

start: check-ports $(docker_compose_yml) testnet_binaries selfcheck-cache-restore
	cd $(net_name); $(docker_compose) up --remove-orphans -d; $(docker_compose) ps
	touch $(net_name)/running.stamp

start_debug: $(docker_compose_yml) testnet_binaries selfcheck-cache-restore
	cd $(net_name); $(docker_compose) up --remove-orphans;
	touch $(net_name)/running.stamp

stop:
	[ -e $(net_name) ] && cd $(net_name) && $(docker_compose) down --remove-orphans; rm -fv running.stamp $(net_name)/servicenode*/courier/*.socket

client-restart:
	@echo "Cleaning and rebuilding kpclientd daemon..."
	rm -fv $(net_name)/kpclientd.$(distro)
	$(MAKE) $(net_name)/kpclientd.$(distro)
	@echo "Restarting kpclientd daemon..."
	cd $(net_name) && $(docker_compose) stop kpclientd
	cd $(net_name) && $(docker_compose) up -d kpclientd
	@echo "kpclientd daemon restarted with updated code"

client-logs:
	@echo "Tailing kpclientd daemon logs (Ctrl+C to exit)..."
	cd $(net_name) && $(docker_compose) logs -f --tail 20 kpclientd

client-logs-snapshot:
	cd $(net_name) && $(docker_compose) logs --tail 200 kpclientd

courier-restart:
	@echo "Stopping courier plugin via thwack management interface..."
	@cd $(net_name) && $(docker_compose) exec -T servicenode1 sh -c 'echo "STOP_KAETZCHEN courier" | /usr/bin/nc -U /$(net_name)/servicenode1/management_sock' || true
	@sleep 1
	@echo "Cleaning and rebuilding courier binary..."
	rm -fv $(net_name)/courier.$(distro)
	$(MAKE) $(net_name)/courier.$(distro)
	@echo "Starting courier plugin via thwack management interface..."
	@cd $(net_name) && $(docker_compose) exec -T servicenode1 sh -c 'echo "START_KAETZCHEN courier" | /usr/bin/nc -U /$(net_name)/servicenode1/management_sock'
	@echo "Courier service restarted with updated code"

replica-restart:
	@echo "Cleaning and rebuilding replica binary..."
	rm -fv $(net_name)/replica.$(distro)
	$(MAKE) $(net_name)/replica.$(distro)
	@echo "Restarting replica containers..."
	@cd $(net_name) && for i in $$(seq 1 $(storageNodes)); do $(docker_compose) restart replica$$i; done
	@echo "Replica containers restarted with updated binary"

servicenode1-restart:
	@echo "Cleaning and rebuilding courier binary..."
	rm -fv $(net_name)/courier.$(distro)
	$(MAKE) $(net_name)/courier.$(distro)
	@echo "Restarting servicenode1 container..."
	cd $(net_name) && $(docker_compose) restart servicenode1
	@echo "Servicenode restarted with updated courier binary"

watch:
	tail -F $(net_name)/*/*.log

# Additional log monitoring targets for debugging
watch-replicas:
	@echo "Monitoring all replica logs (Ctrl+C to exit)..."
	tail -F $(net_name)/replica*/katzenpost.log

watch-auth:
	@echo "Monitoring all directory authority logs (Ctrl+C to exit)..."
	tail -F $(net_name)/auth*/katzenpost.log

watch-mixes:
	@echo "Monitoring all mix node logs (Ctrl+C to exit)..."
	tail -F $(net_name)/mix*/katzenpost.log

watch-courier:
	@echo "Monitoring all courier service logs (Ctrl+C to exit)..."
	tail -F $(net_name)/servicenode*/courier/courier.log

watch-servicenode:
	@echo "Monitoring all service node logs (Ctrl+C to exit)..."
	tail -F $(net_name)/servicenode*/katzenpost.log

watch-gateway:
	@echo "Monitoring gateway log (Ctrl+C to exit)..."
	tail -F $(net_name)/gateway1/katzenpost.log

watch-all-separate:
	@echo "Monitoring all logs with component labels (Ctrl+C to exit)..."
	@echo "Starting log monitoring in background processes..."
	@(tail -F $(net_name)/replica*/katzenpost.log | sed 's/^/[REPLICA] /' &) ; \
	(tail -F $(net_name)/auth*/katzenpost.log | sed 's/^/[AUTH] /' &) ; \
	(tail -F $(net_name)/mix*/katzenpost.log | sed 's/^/[MIX] /' &) ; \
	(tail -F $(net_name)/servicenode*/katzenpost.log | sed 's/^/[SERVICENODE] /' &) ; \
	(tail -F $(net_name)/servicenode*/courier/courier.log | sed 's/^/[COURIER] /' &) ; \
	(tail -F $(net_name)/gateway1/katzenpost.log | sed 's/^/[GATEWAY] /' &) ; \
	wait

# start-with-client-metrics brings the mixnet up with prometheus and grafana
# scraping everything, including kpclientd. The build embeds the
# kpclientd_metrics tag so the daemon registers and serves its /metrics
# endpoint; production builds without the tag still compile out the listener
# entirely.
start-with-client-metrics:
	$(MAKE) start no_metrics=false kpclientd_metrics=true

print-url-grafana:
	@echo "Grafana is provisioned at http://127.0.0.1:$(shell expr $(base_port) + 2002) (default admin/admin on first run)."

print-url-prometheus:
	@echo "Prometheus is provisioned at http://127.0.0.1:$(shell expr $(base_port) + 2001)."

# Pumba chaos. Each start target launches a single chaos container with
# a distinct name; multiple lanes can run side-by-side by passing
# pumba_container=<unique-name> to a second invocation, which is how
# asymmetric latency experiments are set up. Pumba removes the netem
# qdisc when its duration elapses or when the container is stopped,
# restoring normal networking. `pumba-stop` tears down every chaos
# container whose name begins with `katzenpost_pumba_`, regardless of
# which lane started it.
pumba-latency:
	@echo "Starting pumba netem delay: ${pumba_latency_ms}ms jitter=${pumba_jitter_ms}ms distribution=${pumba_distribution} duration=${pumba_duration}"
	@echo "Targets: ${pumba_targets}"
	$(docker) run -d --rm --name $(pumba_container) \
		${pumba_sock_mount} \
		${pumba_image} \
		--log-level info \
		netem --duration ${pumba_duration} --tc-image ${pumba_tc_image} \
		delay --time ${pumba_latency_ms} --jitter ${pumba_jitter_ms} --distribution ${pumba_distribution} ${pumba_correlation_flag} \
		'${pumba_targets}'
	@echo "Pumba running as '$(pumba_container)'. Stop with: make pumba-stop"

pumba-loss:
	@echo "Starting pumba netem loss: ${pumba_loss_pct}% duration=${pumba_duration}"
	@echo "Targets: ${pumba_targets}"
	$(docker) run -d --rm --name $(pumba_container) \
		${pumba_sock_mount} \
		${pumba_image} \
		--log-level info \
		netem --duration ${pumba_duration} --tc-image ${pumba_tc_image} \
		loss --percent ${pumba_loss_pct} ${pumba_loss_corr_flag} \
		'${pumba_targets}'
	@echo "Pumba running as '$(pumba_container)'. Stop with: make pumba-stop"

pumba-corrupt:
	@echo "Starting pumba netem corrupt: ${pumba_corrupt_pct}% duration=${pumba_duration}"
	@echo "Targets: ${pumba_targets}"
	$(docker) run -d --rm --name $(pumba_container) \
		${pumba_sock_mount} \
		${pumba_image} \
		--log-level info \
		netem --duration ${pumba_duration} --tc-image ${pumba_tc_image} \
		corrupt --percent ${pumba_corrupt_pct} \
		'${pumba_targets}'
	@echo "Pumba running as '$(pumba_container)'. Stop with: make pumba-stop"

# pumba-pause freezes the named container for the configured duration.
# The Sphinx unwrap, replica replication, and courier outgoing queues
# should all back up; we verify recovery once the pause ends.
pumba-pause:
	@echo "Pausing $(pumba_pause_target) for ${pumba_pause_duration}"
	$(docker) run -d --rm --name $(pumba_container) \
		${pumba_sock_mount} \
		${pumba_image} \
		--log-level info \
		pause --duration ${pumba_pause_duration} \
		$(pumba_pause_target)
	@echo "Pumba running as '$(pumba_container)'. Stop with: make pumba-stop"

pumba-status:
	@out=$$($(docker) ps --filter "name=^$(pumba_prefix)" --format "{{.Names}}\t{{.Status}}\t{{.Command}}"); \
		if [ -n "$$out" ]; then echo "$$out"; else echo "No pumba chaos container is running."; fi

pumba-stop:
	-@for c in $$($(docker) ps -a --filter "name=^$(pumba_prefix)" --format "{{.Names}}"); do \
		$(docker) stop $(i_if_podman) $$c 2>/dev/null || true; \
		$(docker) rm $(i_if_podman) $$c 2>/dev/null || true; \
	done
	@echo "Pumba chaos cleared."

ps:
	cd $(net_name); $(docker_compose) ps

status:
	@[ -d $(net_name) ] || (echo "./$(net_name)/ does not exist" && false)
	tail -10 $(net_name)/auth1/katzenpost.log
	@echo
	@du -hs ./$(net_name)
	@echo "Current time: $$(TZ=UTC date "+%H:%M:%S %Z") (compare to log timestamps to see if they are current)"
	@cat $(net_name)/auth1/katzenpost.log |grep Genesis|tail -1|while read a b c d; do \
			echo "Network appears to have been running for $$(($$b - $$d)) consecutive epochs:"; \
			grep 'Consensus made' $(net_name)/auth1/katzenpost.log; \
		done|grep . || (echo "(no consensus yet; exiting with error)" && false)

show-latest-vote:
	@grep -A30 'Ready to send' $(net_name)/auth1/katzenpost.log |tail -30|sed /Sending/q

# Generate the bridge-network thinclient config.  The host-network
# thinclient.toml (used by run-ping, run-parallel-load, run-cp-bench)
# dials localhost:base_port+2000 via the compose port forward; this
# variant uses the compose service name kpclientd:<base_port+2000>
# directly. wait needs it because fetch --require-ready probes per-node
# metrics endpoints via container DNS, which is only available on the bridge.
$(net_name)/client/thinclient-bridge.toml: | $(net_name)/client
	@echo '[Dial]'                                       >  $@
	@echo '  [Dial.Tcp]'                                 >> $@
	@echo '    Address = "kpclientd:$(shell expr $(base_port) + 2000)"' >> $@
	@echo '    Network = "tcp"'                          >> $@

wait: $(net_name)/running.stamp $(net_name)/client/thinclient-bridge.toml | $(cache_dir)
	$(docker) run --network=$(compose_network_name) ${docker_args} $(mount_net_name) --rm  katzenpost-$(distro)_base \
	/$(net_name)/fetch.$(distro) -f /$(net_name)/client/thinclient-bridge.toml -r 2 --require-ready

$(distro)_base.stamp: $(base_dockerfile)
	$(docker) build -t katzenpost-$(distro)_base \
		--build-arg BASE_IMAGE=$(base_image) --build-arg GO_VERSION=$(GO_VERSION) \
		-f $(base_dockerfile) .
	touch $@

# Rust build image for pigeonhole-cp, layered on the per-distro base image
# (same C library as the runtime, per-distro cargo caches). Only the
# pigeonhole-cp targets build this; `start`/`wait` stay rust-free.
$(distro)_rust.stamp: Dockerfile.rust $(distro)_base.stamp
	$(docker) build -t katzenpost-$(distro)_rust \
		--build-arg BASE_IMAGE=katzenpost-$(distro)_base \
		-f Dockerfile.rust .
	touch $@

go-mod-tidy: $(distro)_base.stamp | $(net_name) $(cache_dir)
	$(docker) run ${docker_args} katzenpost-$(distro)_base \
			$(sh) -c "go mod tidy"

go-mod-upgrade: $(distro)_base.stamp | $(net_name) $(cache_dir)
	$(docker) run ${docker_args} katzenpost-$(distro)_base \
			$(sh) -c 'go get -d -u ./... && go mod tidy'

$(net_name)/server.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd cmd/server ; go build -trimpath -ldflags ${ldflags} -o /$(net_name)/server.$(distro)'

$(net_name)/courier.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd cmd/courier ; go build -trimpath -ldflags ${ldflags} -o /$(net_name)/courier.$(distro)'

$(net_name)/replica.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd cmd/replica ; go build -trimpath -ldflags ${ldflags} -o /$(net_name)/replica.$(distro)'

$(net_name)/proxy_client.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd cmd/http-proxy-client; go build -trimpath -ldflags ${ldflags} -o /$(net_name)/proxy_client.$(distro)'

$(net_name)/proxy_server.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd cmd/http-proxy-server; go build -trimpath -ldflags ${ldflags} -o /$(net_name)/proxy_server.$(distro)'

$(net_name)/echo_server.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd cmd/echo-plugin ; go build -trimpath -ldflags ${ldflags} -o /$(net_name)/echo_server.$(distro)'

$(net_name)/dirauth.$(distro): $(distro)_base.stamp $(docker_compose_yml) | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd cmd/dirauth && go build $(pyroscope_dirauth_tags) -trimpath -ldflags ${ldflags} -o /$(net_name)/dirauth.$(distro)'

$(net_name)/fetch.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd cmd/fetch && go build -trimpath -ldflags ${ldflags} -o /$(net_name)/fetch.$(distro)'

$(net_name)/ping.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd cmd/ping && go mod verify && go build -ldflags ${ldflags} -o /$(net_name)/ping.$(distro)'

$(net_name)/parallel-load.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd tools/chaos/cmd/parallel-load && go build -ldflags ${ldflags} -o /$(net_name)/parallel-load.$(distro)'

$(net_name)/cp-bench.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd tools/chaos/cmd/cp-bench && go build -ldflags ${ldflags} -o /$(net_name)/cp-bench.$(distro)'

$(net_name)/kpclientd.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd cmd/kpclientd && go mod verify && go build $(kpclientd_tags_flag) -ldflags ${ldflags} -o /$(net_name)/kpclientd.$(distro)'

# Build only the versions that exist; previous is absent until a second
# non-rocksdb release is tagged (see interop_release_refs).
interop-build: $(addprefix interop-build-,$(interop_versions))

interop-compose interop-selfcheck-cache-restore interop-start interop-wait interop-run-ping interop-http-check interop-check interop-check-role interop-smoke interop-client-check interop-activate interop-record-artifact interop-swap-mix interop-swap-gateway interop-swap-servicenode interop-swap-dirauth interop-swap-replica interop-swap-courier interop-swap-http interop-swap-client2 interop-restore-role interop-test interop-report interop-test-baseline interop-test-role interop-test-mixed-network interop-test-quorums interop-stop interop-clean interop-clean-dryrun interop-clean-cache interop-clean-results interop-clean-image interop-clean-all: net_name=$(interop_net_name)

# Ensure the alpine base image the interop recipes run in is built.
interop-image-check: $(distro)_base.stamp
	@test "$(distro)" = alpine || (echo "release interoperability currently supports distro=alpine" >&2; exit 2)

# Build one baseline revision (previous, current, or candidate=HEAD) into
# the interop cache; previous is skipped when no second non-rocksdb release
# exists.
interop-build-previous interop-build-current interop-build-candidate: interop-image-check | $(cache_dir)
	@label=$(@:interop-build-%=%); \
	  case "$$label" in previous) ref='$(previous_ref)';; current) ref='$(current_ref)';; candidate) ref='$(candidate_ref)';; esac; \
	  if [ -z "$$ref" ]; then echo "$${label}_ref is required" >&2; exit 2; fi; \
	  commit=$$(git rev-parse --verify "$$ref^{commit}") || exit; \
	  fingerprint=$$(printf '%s\n' '$(interop_base_image)' '$(GO_VERSION)' '$(warped)' '$(kpclientd_tags_flag)' | cat Dockerfile.base.alpine - | sha256sum | cut -d' ' -f1); \
	  safe_ref=$$(printf '%s' "$$ref" | tr -c 'A-Za-z0-9._-' '-' | cut -c1-48); artifact="$$label-$$safe_ref-$$(printf '%.12s' "$$commit")-$$(printf '%.8s' "$$fingerprint")"; \
	  out="$(interop_dir)/$$label"; src="$(interop_dir)/src/$$label"; \
	  valid=true; \
	  [ -f "$$out/commit" ] && [ "$$(cat "$$out/commit")" = "$$commit" ] || valid=false; \
	  [ -f "$$out/ref" ] && [ "$$(cat "$$out/ref")" = "$$ref" ] || valid=false; \
	  [ -f "$$out/artifact" ] && [ "$$(cat "$$out/artifact")" = "$$artifact" ] || valid=false; \
	  [ -f "$$out/fingerprint" ] && [ "$$(cat "$$out/fingerprint")" = "$$fingerprint" ] || valid=false; \
	  [ -f "$$out/format" ] && [ "$$(cat "$$out/format")" = 3 ] || valid=false; \
	  for bin in $(interop_build_bins); do [ -x "$$out/$$bin.$(distro).$$artifact" ] || valid=false; done; \
	  if [ "$$valid" != true ]; then \
	    echo "Building interop $$label ($$ref -> $$commit)"; \
	    rm -rf "$$src" "$$out"; mkdir -p "$$src" "$$out"; \
	    git -C .. archive "$$commit" | tar -x -C "$$src"; \
	    $(docker) run --user $(docker_user) --rm --pids-limit 4096 \
	      -v "$$(readlink -f "$(go_mod_cache)"):/go/" \
	      -v "$$(readlink -f "$$src"):/go/katzenpost:ro" \
	      -v "$$(readlink -f "$$out"):/interop-out" \
	      -v "$$(readlink -f "$(go_build_cache)"):/gocache/" \
	      -e GOCACHE=/gocache -e GOPATH=/go -e INTEROP_ARTIFACT="$$artifact" -e INTEROP_COMMIT="$$commit" --workdir /go/katzenpost \
	      $(interop_image) $(sh) -c '\
	        set -eu; \
	        flags="-extldflags=-Wl,-z,stack-size=0x1F40000 -buildid= -X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=$(warped) -X github.com/carlmjohnson/versioninfo.Revision=$${INTEROP_COMMIT}"; \
	        go build -trimpath -ldflags "$$flags" -o /interop-out/server.$(distro).$${INTEROP_ARTIFACT} ./cmd/server; \
	        go build -trimpath -ldflags "$$flags" -o /interop-out/dirauth.$(distro).$${INTEROP_ARTIFACT} ./cmd/dirauth; \
	        go build -trimpath -ldflags "$$flags" -o /interop-out/replica.$(distro).$${INTEROP_ARTIFACT} ./cmd/replica; \
	        go build -trimpath -ldflags "$$flags" -o /interop-out/courier.$(distro).$${INTEROP_ARTIFACT} ./cmd/courier; \
	        go build $(kpclientd_tags_flag) -trimpath -ldflags "$$flags" -o /interop-out/kpclientd.$(distro).$${INTEROP_ARTIFACT} ./cmd/kpclientd; \
	        go build -trimpath -ldflags "$$flags" -o /interop-out/fetch.$(distro).$${INTEROP_ARTIFACT} ./cmd/fetch; \
	        go build -trimpath -ldflags "$$flags" -o /interop-out/ping.$(distro).$${INTEROP_ARTIFACT} ./cmd/ping; \
	        go build -trimpath -ldflags "$$flags" -o /interop-out/proxy_server.$(distro).$${INTEROP_ARTIFACT} ./cmd/http-proxy-server; \
	        go build -trimpath -ldflags "$$flags" -o /interop-out/proxy_client.$(distro).$${INTEROP_ARTIFACT} ./cmd/http-proxy-client; \
	        go build -trimpath -ldflags "$$flags" -o /interop-out/genconfig.$(distro).$${INTEROP_ARTIFACT} ./cmd/genconfig; \
	        go test -c -trimpath -tags=docker_test -ldflags "$$flags" -o /interop-out/client_tests.$(distro).$${INTEROP_ARTIFACT} ./client' || exit; \
	    for bin in $(interop_build_bins); do test -x "$$out/$$bin.$(distro).$$artifact" || exit 1; done; \
	    printf '%s\n' "$$commit" > "$$out/commit"; \
	    printf '%s\n' "$$ref" > "$$out/ref"; \
	    printf '%s\n' "$$artifact" > "$$out/artifact"; \
	    printf '%s\n' "$$fingerprint" > "$$out/fingerprint"; \
	    printf '%s\n' 3 > "$$out/format"; \
	  else echo "Using cached interop $$label ($$commit)"; fi

# Materialise every service's per-service binary for a baseline and record
# it in runtime-artifacts.tsv.
interop-activate: interop-selfcheck-cache-restore | $(net_name)
	@case "$(BASELINE)" in previous|current|candidate) ;; *) echo "BASELINE must be previous, current, or candidate" >&2; exit 2;; esac
	@artifact=$$(cat $(interop_dir)/$(BASELINE)/artifact); for bin in $(interop_probe_bins); do \
	  install -m 0755 "$(interop_dir)/$(BASELINE)/$$bin.$(distro).$$artifact" "$(net_name)/$$bin.$(distro).new"; \
	  mv -f "$(net_name)/$$bin.$(distro).new" "$(net_name)/$$bin.$(distro)"; \
	done
	@printf 'SERVICE\tROLE\tBINARY\tARTIFACT\tREF\tCOMMIT\n' > $(net_name)/runtime-artifacts.tsv
	@printf '%s\t%s\t%s\n' $(BASELINE) $$(cat $(interop_dir)/$(BASELINE)/artifact) $$(cat $(interop_dir)/$(BASELINE)/commit) > $(net_name)/runtime-baseline.tsv
	@set -e; artifact=$$(cat $(interop_dir)/$(BASELINE)/artifact); \
	  for role in $(interop_roles); do \
	    case "$$role" in \
	      mix) services='$(interop_services_mix)'; bins=server;; \
	      gateway) services='$(interop_services_gateway)'; bins=server;; \
	      servicenode) services='$(interop_services_servicenode)'; bins=server;; \
	      dirauth) services='$(interop_services_dirauth)'; bins=dirauth;; \
	      replica) services='$(interop_services_replica)'; bins=replica;; \
	      courier) services='$(interop_services_courier)'; bins=courier;; \
	      http) services='$(interop_services_http)'; bins=proxy_server;; \
	      client2) services='$(interop_services_client2)'; bins='kpclientd fetch ping proxy_client';; \
	    esac; \
	    for service in $$services; do \
	      for bin in $$bins; do install -m 0755 "$(interop_dir)/$(BASELINE)/$$bin.$(distro).$$artifact" "$(net_name)/$$bin.$(distro).$$service.new"; \
	        mv -f "$(net_name)/$$bin.$(distro).$$service.new" "$(net_name)/$$bin.$(distro).$$service"; done; \
	      $(MAKE) --no-print-directory SERVICE=$$service ROLE=$$role BINS="$$bins" VERSION=$(BASELINE) interop-record-artifact; \
	    done; \
	  done
	@if [ "$(DEBUG)" = 1 ]; then cat $(net_name)/runtime-artifacts.tsv; fi
	@echo "Activated $(BASELINE) ($$(cat $(interop_dir)/$(BASELINE)/commit)) for the complete network"

# Record which artifact/commit a service currently runs into
# runtime-artifacts.tsv.
interop-record-artifact:
	@artifact=$$(cat $(interop_dir)/$(VERSION)/artifact); ref=$$(cat $(interop_dir)/$(VERSION)/ref); commit=$$(cat $(interop_dir)/$(VERSION)/commit); \
	  for bin in $(BINS); do tmp=$(net_name)/runtime-artifacts.tsv.new; \
	    awk -F '\t' -v service='$(SERVICE)' -v binary="$$bin" 'BEGIN { OFS="\t" } NR == 1 || !($$1 == service && $$3 == binary)' $(net_name)/runtime-artifacts.tsv > "$$tmp"; \
	    printf '%s\t%s\t%s\t%s\t%s\t%s\n' '$(SERVICE)' '$(ROLE)' "$$bin" "$$artifact" "$$ref" "$$commit" >> "$$tmp"; \
	    mv -f "$$tmp" $(net_name)/runtime-artifacts.tsv; \
	  done

# Generate the interop docker-compose network and rewrite each service to
# its per-service binary path.
interop-compose: interop-build | $(net_name) $(cache_dir)
	@-cd $(net_name) && $(docker_compose) down --remove-orphans
	git clean -fdx $(net_name)
	mkdir -p $(net_name)
	$(docker) run --user $(docker_user) --rm --pids-limit 4096 \
		-v $(shell readlink -f $(interop_dir)/$(BASELINE)):/interop-bin:ro \
		-v $(shell readlink -f $(net_name)):/work/$(net_name) --workdir /work \
		$(interop_image) /interop-bin/genconfig.$(distro).$(shell cat $(interop_dir)/$(BASELINE)/artifact 2>/dev/null) \
			$(interop_genconfig_args) --binSuffix .$(distro) --voting \
		--outDir ./$(net_name) --baseDir /$(net_name) --port $(base_port) \
		--dockerImage $(interop_image)
	@for spec in $(interop_compose_bins); do \
	  service=$${spec%%:*}; bin=$${spec##*:}; sed -i "s|/$$bin.$(distro) -f /$(net_name)/$$service/|/$$bin.$(distro).$$service -f /$(net_name)/$$service/|" $(net_name)/docker-compose.yml; done
	@sed -i "s|/kpclientd.$(distro) -c /$(net_name)/client/|/kpclientd.$(distro).kpclientd -c /$(net_name)/client/|" $(net_name)/docker-compose.yml
	@for service in $(interop_services_servicenode); do \
	  sed -i "s|/courier.$(distro)\"|/courier.$(distro).$$service\"|; s|/proxy_server.$(distro)\"|/proxy_server.$(distro).$$service\"|" $(net_name)/$$service/katzenpost.toml; done
	install -m 0644 interop-http-server.pl $(net_name)/interop-http-server.pl
	@addr=$$(sed -n '/^\[Listen\]/,$$ { s/^[[:space:]]*Address = "\([^"]*\)".*/\1/p; }' $(net_name)/client/client.toml | head -1); \
	  [ -n "$$addr" ] || { echo "client listen address not found" >&2; exit 1; }; \
	  printf '[Dial]\n  [Dial.Tcp]\n    Address = "kpclientd:%s"\n' "$${addr##*:}" > $(net_name)/client/thinclient-bridge.toml

# Copy committed selfcheck sidecars into each service dir so boot-time
# self-checks are skipped.
interop-selfcheck-cache-restore: interop-compose
	@if [ -d selfcheck-cache ]; then \
	  for f in selfcheck-cache/*.toml; do \
	    svc=$$(basename $$f .toml); \
	    if [ -d "$(net_name)/$$svc" ]; then \
	      cp "$$f" "$(net_name)/$$svc/selfcheck.toml"; \
	    fi; \
	  done; \
	fi

# Activate a baseline across the whole network and bring the containers up.
interop-start: interop-activate
	cd $(net_name); $(docker_compose) up --remove-orphans --force-recreate -d; $(docker_compose) ps
	touch $(net_name)/running.stamp

# Block until every node reports ready against the current consensus.
interop-wait:
	@test -f $(net_name)/running.stamp || (echo "run make interop-start first" >&2; exit 2)
	@$(docker) network inspect $(compose_network_name) >/dev/null 2>&1 || { echo "PHASE baseline=$(BASELINE) role=$(ROLE) status=infra-fail detail=network-missing" >&2; exit 1; }
	@case "$(FETCH_VERSION)" in previous|current|candidate) ;; *) echo "FETCH_VERSION must be previous, current, or candidate" >&2; exit 2;; esac
	@test -s $(interop_dir)/$(FETCH_VERSION)/artifact || { echo "interop artifacts not built for $(FETCH_VERSION); run make interop-build" >&2; exit 2; }
	@out=$$(mktemp); cleanup() { rm -f "$$out"; }; trap cleanup EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; \
	  deadline=$$(($$(date +%s) + $(interop_consensus_timeout))); attempt=0; while :; do \
	    attempt=$$((attempt + 1)); \
	    remaining=$$((deadline - $$(date +%s))); echo "PHASE baseline=$(BASELINE) role=$(ROLE) component=$(COMPONENT_VERSION) check=client-daemon status=probing attempt=$$attempt timeout=$(interop_fetch_timeout) remaining=$${remaining}s"; \
	    if timeout $(interop_fetch_timeout) $(docker) run $(replace_name) katzenpost_interop_probe --network=$(compose_network_name) ${docker_args} $(mount_net_name) \
	      -v $(shell readlink -f $(interop_dir)/$(FETCH_VERSION)):/interop-fetch:ro --rm $(interop_image) \
	      /interop-fetch/fetch.$(distro).$(shell cat $(interop_dir)/$(FETCH_VERSION)/artifact 2>/dev/null) -f /$(net_name)/client/thinclient-bridge.toml \
	      -r $(storageNodes) > "$$out" 2>&1; then \
	      epoch=$$(sed -n 's/^PKI document for epoch \([0-9][0-9]*\).*/\1/p' "$$out" | tail -1); \
	    else \
	      epoch=''; latest=$$(grep -E 'Failed to connect|failed|ERROR|Error' "$$out" | tail -1 || true); \
	      [ -n "$$latest" ] || latest=$$(sed -n '/[^[:space:]]/p' "$$out" | tail -1); remaining=$$((deadline - $$(date +%s))); \
	      if grep -Eqi 'unable to find network|network .*not found|no network with (name|ID)' "$$out"; then cat "$$out"; echo "PHASE baseline=$(BASELINE) role=$(ROLE) status=infra-fail detail=network-missing" >&2; exit 1; fi; \
	      [ $$(date +%s) -lt $$deadline ] || { cat "$$out"; echo "client daemon did not become ready" >&2; exit 1; }; \
	      echo "PHASE baseline=$(BASELINE) role=$(ROLE) component=$(COMPONENT_VERSION) check=client-daemon status=retry attempt=$$attempt remaining=$${remaining}s detail=$$latest"; sleep 5; continue; \
	    fi; \
	    if [ -n "$$epoch" ] && { [ -z "$(WAIT_AFTER_EPOCH)" ] || [ "$$epoch" -gt "$(WAIT_AFTER_EPOCH)" ]; }; then break; fi; \
	    [ $$(date +%s) -lt $$deadline ] || { cat "$$out"; echo "no consensus newer than epoch $(WAIT_AFTER_EPOCH)" >&2; exit 1; }; \
	    remaining=$$((deadline - $$(date +%s))); echo "PHASE baseline=$(BASELINE) role=$(ROLE) component=$(COMPONENT_VERSION) check=next-consensus current=$$epoch after=$(WAIT_AFTER_EPOCH) attempt=$$attempt remaining=$${remaining}s"; sleep 5; \
	  done; cat "$$out"; printf '%s\n' "$$epoch" > $(net_name)/interop.last_epoch; \
	  for auth in $(EXPECT_AUTHS); do grep -q "^  $$auth (" "$$out" || { echo "$$auth did not sign the consensus" >&2; exit 1; }; done
	@timeout $(interop_readiness_timeout) $(docker) run $(replace_name) katzenpost_interop_probe --network=$(compose_network_name) ${docker_args} $(mount_net_name) --rm $(interop_image) $(sh) -c '\
	  set -eu; tmp=$$(mktemp -d); cleanup() { rm -rf "$$tmp"; }; trap cleanup EXIT; trap '\''exit 129'\'' HUP; trap '\''exit 130'\'' INT; trap '\''exit 143'\'' TERM; pids=""; n=0; \
	  for cfg in /$(net_name)/gateway*/katzenpost.toml /$(net_name)/mix*/katzenpost.toml \
	    /$(net_name)/servicenode*/katzenpost.toml /$(net_name)/replica*/replica.toml \
	    /$(net_name)/servicenode*/courier/courier.toml; do \
	    n=$$((n + 1)); { addr=$$(sed -n '\''s/^[[:space:]]*MetricsAddress = "\([^" ]*\)".*/\1/p'\'' "$$cfg" | head -1); \
	      [ -n "$$addr" ] || { echo "missing metrics address in $$cfg"; exit 1; }; \
	      ready=false; for attempt in $$(seq 1 120); do if curl -fsS --max-time 3 "http://$$addr/metrics" >/dev/null 2>&1; then ready=true; break; fi; sleep 2; done; \
	      [ "$$ready" = true ] || { echo "metrics unavailable for $$cfg at $$addr"; exit 1; }; \
	      printf "READY %-24s %s\n" $$(basename $$(dirname "$$cfg")) "$$addr"; } > "$$tmp/$$n" 2>&1 & pids="$$pids $$!"; \
	  done; failed=0; for pid in $$pids; do wait $$pid || failed=1; done; cat "$$tmp"/*; exit $$failed'

# Send pings through the running network and fail unless all are answered.
interop-run-ping:
	@test -s $(interop_dir)/$(CHECK_CLIENT_VERSION)/artifact || { echo "interop artifacts not built for $(CHECK_CLIENT_VERSION); run make interop-build" >&2; exit 2; }
	@out=$$(mktemp); cleanup() { rm -f "$$out"; }; trap cleanup EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; attempt=1; \
	  while [ $$attempt -le $(interop_ping_attempts) ]; do \
	    if timeout $(interop_ping_timeout) $(docker) run $(replace_name) katzenpost_interop_ping --network=host --user $(docker_user) $(mount_net_name) \
	      -v $(shell readlink -f $(interop_dir)/$(CHECK_CLIENT_VERSION)):/interop-ping:ro --rm $(interop_image) \
	      /interop-ping/ping.$(distro).$(shell cat $(interop_dir)/$(CHECK_CLIENT_VERSION)/artifact 2>/dev/null) --thin -c /$(net_name)/client/thinclient.toml -s echo --print-diff -n $(INTEROP_PINGS) > "$$out" 2>&1; then \
	      cat "$$out"; grep -q "Success rate is 100 percent ($(INTEROP_PINGS)/$(INTEROP_PINGS))" "$$out" && exit 0; \
	    else cat "$$out"; fi; \
	    echo "PHASE check=echo-ping retry=$$attempt/$(interop_ping_attempts)"; attempt=$$((attempt + 1)); sleep 5; \
	  done; echo "echo ping failed" >&2; exit 1

# Exercise the HTTP proxy service end to end against the running network.
interop-http-check:
	@case "$(CHECK_HTTP_VERSION)" in previous|current|candidate) ;; *) echo "CHECK_HTTP_VERSION must be previous, current, or candidate" >&2; exit 2;; esac
	@test -s $(interop_dir)/$(CHECK_HTTP_VERSION)/artifact || { echo "interop artifacts not built for $(CHECK_HTTP_VERSION); run make interop-build" >&2; exit 2; }
	@cd $(net_name) && for service in $(interop_services_http); do \
	  $(docker_compose) exec -T "$$service" sh -c 'nohup perl /$(net_name)/interop-http-server.pl >>/tmp/interop-http.log 2>&1 &'; \
	  $(docker_compose) exec -T "$$service" sh -c 'for i in $$(seq 1 20); do perl -e "use IO::Socket::INET; exit(IO::Socket::INET->new(PeerAddr=>q{127.0.0.1:4242}) ? 0 : 1)" && exit 0; sleep 1; done; echo "interop http server not listening on $$service" >&2; cat /tmp/interop-http.log >&2; exit 1'; \
	done
	@$(docker) run $(replace_name) katzenpost_interop_http --network=$(compose_network_name) ${docker_args} $(mount_net_name) \
		-v $(shell readlink -f $(interop_dir)/$(CHECK_HTTP_VERSION)):/interop-http:ro --rm $(interop_image) $(sh) -c '\
	  set -eu; cleanup() { [ -z "$${pid:-}" ] || kill "$$pid" 2>/dev/null || true; }; trap cleanup EXIT; trap '\''exit 129'\'' HUP; trap '\''exit 130'\'' INT; trap '\''exit 143'\'' TERM; \
	  /interop-http/proxy_client.$(distro).$(shell cat $(interop_dir)/$(CHECK_HTTP_VERSION)/artifact 2>/dev/null) -cfg /$(net_name)/client/thinclient-bridge.toml -retry 20 -delay 2 -port 8080 >/tmp/proxy.log 2>&1 & pid=$$!; \
	  for n in $$(seq 1 10); do if NO_PROXY= no_proxy= curl -fsS --max-time 70 -x http://127.0.0.1:8080 http://localhost:4242/ | grep -q interop-http-ok; then echo "HTTP proxy round trip passed with $(CHECK_HTTP_VERSION) client"; exit; fi; sleep 2; done; \
	  cat /tmp/proxy.log >&2; exit 1'

# Run the full functional check (wait, ping, HTTP, and client tests)
# against the network.
interop-check:
	@expected=$$(cat $(interop_dir)/$(BASELINE)/artifact); \
	  if [ ! -f $(net_name)/running.stamp ] || ! $(docker) network inspect $(compose_network_name) >/dev/null 2>&1 || ! grep -q "^$(BASELINE)[[:space:]]$$expected[[:space:]]" $(net_name)/runtime-baseline.tsv 2>/dev/null; then \
	    $(MAKE) --no-print-directory interop-stop >/dev/null 2>&1 || true; $(MAKE) -j1 BASELINE=$(BASELINE) interop-start; \
	  fi
	@$(MAKE) -j1 net_name=$(interop_net_name) FETCH_VERSION=$(CHECK_CLIENT_VERSION) interop-wait interop-run-ping CHECK_HTTP_VERSION=$(CHECK_HTTP_VERSION) interop-http-check CHECK_CLIENT_VERSION=$(CHECK_CLIENT_VERSION) interop-client-check

# Run interop-check for one role's services, reporting per-service results.
interop-check-role:
	@echo "PHASE baseline=$(BASELINE) role=$(ROLE) component=$(COMPONENT_VERSION) check=consensus-and-processes"
	@$(MAKE) -j1 net_name=$(interop_net_name) BASELINE=$(BASELINE) ROLE=$(ROLE) COMPONENT_VERSION=$(COMPONENT_VERSION) FETCH_VERSION=$(if $(filter client2,$(ROLE)),$(COMPONENT_VERSION),$(BASELINE)) WAIT_AFTER_EPOCH=$(WAIT_AFTER_EPOCH) EXPECT_AUTHS="$(if $(filter dirauth,$(ROLE)),$(EXPECT_AUTHS))" interop-wait
	@case "$(ROLE)" in \
	  mix|gateway|servicenode|dirauth) echo "PHASE baseline=$(BASELINE) role=$(ROLE) component=$(COMPONENT_VERSION) check=echo-ping"; $(MAKE) -j1 net_name=$(interop_net_name) INTEROP_PINGS=1 interop-run-ping;; \
	  replica|courier) echo "PHASE baseline=$(BASELINE) role=$(ROLE) component=$(COMPONENT_VERSION) check=pigeonhole"; $(MAKE) -j1 net_name=$(interop_net_name) CHECK_CLIENT_VERSION=$(BASELINE) interop-client-check;; \
	  http) echo "PHASE baseline=$(BASELINE) role=$(ROLE) component=$(COMPONENT_VERSION) check=http"; $(MAKE) -j1 net_name=$(interop_net_name) CHECK_HTTP_VERSION=$(BASELINE) interop-http-check;; \
	  client2) echo "PHASE baseline=$(BASELINE) role=$(ROLE) component=$(COMPONENT_VERSION) check=client-suite"; $(MAKE) -j1 net_name=$(interop_net_name) INTEROP_PINGS=1 interop-run-ping CHECK_HTTP_VERSION=$(COMPONENT_VERSION) interop-http-check CHECK_CLIENT_VERSION=$(COMPONENT_VERSION) interop-client-check;; \
	  *) echo "unsupported ROLE=$(ROLE)" >&2; exit 2;; \
	esac

# Build the revisions and run one quick end-to-end interop check (used by
# the pre-push hook).
interop-smoke: interop-build
	@set -e; cleanup() { $(MAKE) --no-print-directory interop-stop >/dev/null 2>&1 || true; }; \
	  trap cleanup EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; $(MAKE) -j1 BASELINE=$(BASELINE) CHECK_CLIENT_VERSION=$(CHECK_CLIENT_VERSION) interop-check

# Run the compiled pigeonhole client tests against the running network.
interop-client-check:
	@case "$(CHECK_CLIENT_VERSION)" in previous|current|candidate) ;; *) echo "CHECK_CLIENT_VERSION must be previous, current, or candidate" >&2; exit 2;; esac
	@test -s $(interop_dir)/$(CHECK_CLIENT_VERSION)/artifact || { echo "interop artifacts not built for $(CHECK_CLIENT_VERSION); run make interop-build" >&2; exit 2; }
	$(docker) run --network=host --user $(docker_user) --rm --pids-limit 4096 \
		-v $(shell readlink -f $(net_name)):/interop-net:ro \
		-v $(shell readlink -f $(interop_dir)/$(CHECK_CLIENT_VERSION)):/interop-bin:ro \
		--workdir /tmp $(interop_image) $(sh) -c 'mkdir -p client-test/testdata; \
		cp /interop-net/client/client.toml /interop-net/client/thinclient.toml client-test/testdata/; \
		cd client-test; /interop-bin/client_tests.$(distro).$(shell cat $(interop_dir)/$(CHECK_CLIENT_VERSION)/artifact 2>/dev/null) -test.v -test.timeout=15m \
		-test.run "^TestNewPigeonholeAPIAliceSendsBob$$" 2>&1 | tee /tmp/client-test.log; \
		grep -q "^--- PASS: TestNewPigeonholeAPIAliceSendsBob" /tmp/client-test.log'

# Do nothing; used as the check target when a swap should skip its
# post-swap check.
interop-noop:

# Check the topology preconditions the suite relies on without building
# images or starting Podman.
interop-validate:
	@set -eu; \
	  for role in $(interop_roles); do case $$role in mix|gateway|servicenode|dirauth|replica|courier|http|client2) ;; *) echo "unknown interop role: $$role" >&2; exit 1;; esac; done; \
	  for svc in '$(interop_services_mix)' '$(interop_services_gateway)' '$(interop_services_servicenode)' '$(interop_services_dirauth)' '$(interop_services_replica)'; do \
	    [ -n "$$svc" ] || { echo "empty interop service list; check the topology variables" >&2; exit 1; }; done; \
	  nversions=$$(echo $(interop_versions) | wc -w); \
	  nonbase=$$(echo $(filter-out $(BASELINE),$(interop_versions)) | wc -w); \
	  if [ "$$nonbase" -ge 2 ]; then quorums=" + quorums"; \
	    [ $(auths) -ge 3 ] || { echo "interop-test-quorums needs auths >= 3 (have $(auths))" >&2; exit 1; }; \
	    [ $(storageNodes) -ge 5 ] || { echo "interop-test-quorums needs storageNodes >= 5 (have $(storageNodes))" >&2; exit 1; }; \
	  else quorums=" (quorums skipped until a second non-rocksdb release)"; fi; \
	  printf 'Interop plan valid: %s roles x %s baselines%s (auths=%s replicas=%s)\n' $$(printf '%s\n' $(interop_roles) | wc -l) "$$nversions" "$$quorums" '$(auths)' '$(storageNodes)'

# Swap one role's (mix, gateway, servicenode, dirauth, replica, courier,
# http, client2) binary to COMPONENT_VERSION, verify the service came back
# up on that revision from its log, and re-check the network.
interop-swap-mix interop-swap-gateway interop-swap-servicenode interop-swap-dirauth interop-swap-replica interop-swap-courier interop-swap-http interop-swap-client2: interop-build
	@set -e; role=$(@:interop-swap-%=%); \
	  case "$(COMPONENT_VERSION)" in previous|current|candidate) ;; *) echo "COMPONENT_VERSION must be previous, current, or candidate" >&2; exit 2;; esac; \
	  case "$$role" in \
	    mix) services='$(interop_services_mix)'; bins=server;; gateway) services='$(interop_services_gateway)'; bins=server;; \
	    servicenode) services='$(interop_services_servicenode)'; bins=server;; dirauth) services='$(interop_services_dirauth)'; bins=dirauth;; \
	    replica) services='$(interop_services_replica)'; bins=replica;; \
	    courier) services='$(interop_services_courier)'; bins=courier;; \
	    http) services='$(interop_services_http)'; bins=proxy_server;; \
	    client2) services='$(interop_services_client2)'; bins='kpclientd fetch ping proxy_client';; \
	  esac; \
	  service='$(SERVICE)'; if [ -z "$$service" ]; then set -- $$services; service=$$1; fi; \
	  case " $$services " in *" $$service "*) ;; *) echo "SERVICE=$$service is not a $$role service" >&2; exit 2;; esac; \
	  artifact=$$(cat $(interop_dir)/$(COMPONENT_VERSION)/artifact); \
	  echo "baseline=$(BASELINE) role=$$role service=$$service component=$(COMPONENT_VERSION) artifact=$$artifact commit=$$(cat $(interop_dir)/$(COMPONENT_VERSION)/commit)"; \
	  commit=$$(cat $(interop_dir)/$(COMPONENT_VERSION)/commit); \
	  revcount() { if [ "$$role" = client2 ]; then (cd "$(net_name)" && $(docker_compose) logs "$$service" 2>/dev/null) | grep -c " rev $$commit" || true; \
	    else cat "$(net_name)/$$service/katzenpost.log" "$(net_name)/$$service/courier/courier.log" "$(net_name)/$$service"/proxy.*.log 2>/dev/null | grep -c " rev $$commit" || true; fi; }; \
	  if [ "$(SWAP_RUNNING)" = true ]; then before=$$(revcount); cd "$(net_name)" && $(docker_compose) stop "$$service"; cd ..; fi; \
	  for bin in $$bins; do \
	    install -m 0755 "$(interop_dir)/$(COMPONENT_VERSION)/$$bin.$(distro).$$artifact" "$(net_name)/$$bin.$(distro).$$service.new"; \
	    mv -f "$(net_name)/$$bin.$(distro).$$service.new" "$(net_name)/$$bin.$(distro).$$service"; \
	  done; \
	  if [ "$(SWAP_RUNNING)" = true ]; then \
	    cd "$(net_name)" && $(docker_compose) start "$$service"; cd ..; \
	    ok=false; for i in $$(seq 1 30); do if [ "$$(revcount)" -gt "$${before:-0}" ]; then ok=true; break; fi; sleep 2; done; \
	    [ "$$ok" = true ] || { echo "swap verify: $$service did not come up running rev $$commit" >&2; exit 1; }; \
	  fi; \
	  $(MAKE) --no-print-directory SERVICE=$$service ROLE=$$role BINS="$$bins" VERSION=$(COMPONENT_VERSION) interop-record-artifact
	@$(MAKE) -j1 net_name=$(interop_net_name) WAIT_AFTER_EPOCH=$(shell cat $(net_name)/interop.last_epoch 2>/dev/null) EXPECT_AUTHS=$(if $(filter dirauth,$(@:interop-swap-%=%)),$(SERVICE)) CHECK_HTTP_VERSION=$(if $(filter client2,$(@:interop-swap-%=%)),$(COMPONENT_VERSION),$(BASELINE)) CHECK_CLIENT_VERSION=$(if $(filter client2,$(@:interop-swap-%=%)),$(COMPONENT_VERSION),$(BASELINE)) $(interop_check_target)

# Swap a role's service back to the baseline revision.
interop-restore-role:
	@$(MAKE) -j1 BASELINE=$(BASELINE) COMPONENT_VERSION=$(BASELINE) SERVICE=$(SERVICE) interop_check_target=interop-noop interop-swap-$(ROLE)

# Run the full interop matrix: baselines, mixed networks, per-role swaps,
# and quorums.
interop-test: interop-validate interop-build
	@child=''; monitor=''; debug_tail=''; cleanup() { [ -z "$$debug_tail" ] || kill "$$debug_tail" 2>/dev/null || true; [ -z "$$monitor" ] || kill "$$monitor" 2>/dev/null || true; if [ -n "$$child" ]; then kill -INT "$$child" 2>/dev/null || true; n=0; while kill -0 "$$child" 2>/dev/null && [ $$n -lt 5 ]; do sleep 1; n=$$((n + 1)); done; kill -KILL "$$child" 2>/dev/null || true; wait "$$child" 2>/dev/null || true; fi; $(interop_stop_make) --no-print-directory interop-stop >/dev/null 2>&1 || true; }; \
	  trap cleanup EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; \
	  fmt() { printf '%02d:%02d:%02d' $$(($$1 / 3600)) $$(($$1 / 60 % 60)) $$(($$1 % 60)); }; \
	  case '$(interop_report_dir)' in ''|.|..|/*) echo 'interop_report_dir must be a non-empty relative path' >&2; exit 2;; esac; \
	  rm -rf '$(interop_report_dir)'; mkdir -p '$(interop_report_dir)/logs'; \
	  if [ "$(DEBUG)" = 1 ]; then find '$(interop_dir)' -type f -perm -0100 -print | sort | sed 's/^/BINARY /'; fi; \
	  printf 'VERSION\tREF\tCOMMIT\tARTIFACT\n' > $(interop_report_dir)/revisions.tsv; \
	  for version in $(interop_versions); do case $$version in previous) ref='$(previous_ref)';; current) ref='$(current_ref)';; candidate) ref='$(candidate_ref)';; esac; \
	    commit=$$(cat $(interop_dir)/$$version/commit); artifact=$$(cat $(interop_dir)/$$version/artifact); printf '%s\t%s\t%s\t%s\n' $$version $$ref $$commit $$artifact >> $(interop_report_dir)/revisions.tsv; \
	    printf 'REV  %-9s %-16s %s %s\n' $$version $$ref $$commit $$artifact; done; \
	  set -- $(interop_roles) quorums; role_count=$$#; set -- $(interop_versions); version_count=$$#; set -- $(interop_network_versions); network_count=$$#; total=$$((version_count * role_count + network_count + 1)); \
	  printf 'PLAN 1 all-version + %d homogeneous + %d role legs, heartbeat %ss\n' $$network_count $$((version_count * role_count)) $(interop_heartbeat); \
	  printf 'BASELINE\tROLE\tRESULT\tSECONDS\tLOG\n' > $(interop_report_dir)/report.tsv; \
	  failed=0; completed=0; completed_seconds=0; index=0; active_baseline=''; matrix_started=$$(date +%s); \
	  for spec in candidate/mixed-network $(foreach version,$(interop_network_versions),$(version)/network) $(foreach version,$(interop_versions),$(foreach role,$(interop_roles) quorums,$(version)/$(role))); do \
	    baseline=$${spec%/*}; role=$${spec#*/}; \
	    if [ "$$role" = network ] || [ "$$role" = mixed-network ] || [ "$$baseline" != "$$active_baseline" ]; then $(interop_stop_make) --no-print-directory interop-stop >/dev/null 2>&1 || true; fi; \
	    case $$role in network|mixed-network) active_baseline='';; *) active_baseline=$$baseline;; esac; \
	    index=$$((index + 1)); log=$(interop_report_dir)/logs/$$baseline-$$role.log; \
	    case $$baseline in previous) ref='$(previous_ref)';; current) ref='$(current_ref)';; candidate) ref='$(candidate_ref)';; esac; \
	    commit=$$(cat $(interop_dir)/$$baseline/commit); overall=$$(($$(date +%s) - matrix_started)); \
	    eval role_total=\$${role_total_$$role:-0}; eval role_done=\$${role_done_$$role:-0}; \
	    if [ $$role_done -gt 0 ]; then role_average=$$((role_total / role_done)); elif [ $$completed -gt 0 ]; then role_average=$$((completed_seconds / completed)); else role_average=$(interop_initial_leg_seconds); fi; \
	    if [ $$completed -gt 0 ]; then average=$$((completed_seconds / completed)); else average=$(interop_initial_leg_seconds); fi; eta=$$((role_average + average * (total - index))); eta=$$(fmt $$eta); \
	    printf 'RUN  %02d/%02d %-9s %-12s ref=%s@%.12s elapsed=%s eta=%s\n' $$index $$total $$baseline $$role $$ref $$commit $$(fmt $$overall) $$eta; \
	    started=$$(date +%s); case $$role in network) target=interop-smoke;; mixed-network) target=interop-test-mixed-network;; *) target=interop-test-role;; esac; \
	    timeout --foreground --kill-after=5s $(interop_leg_timeout) $(interop_submake) -j1 BASELINE=$$baseline ROLE=$$role REUSE_NETWORK=true DEBUG=$(DEBUG) $$target > $$log 2>&1 & child=$$!; \
	    if [ "$(DEBUG)" = 1 ]; then tail -n +1 -F --pid=$$child $$log & debug_tail=$$!; fi; \
	    (while kill -0 $$child 2>/dev/null; do sleep $(interop_heartbeat); kill -0 $$child 2>/dev/null || exit; \
	      leg_elapsed=$$(($$(date +%s) - started)); overall=$$(($$(date +%s) - matrix_started)); \
	      if [ $$completed -gt 0 ]; then average=$$((completed_seconds / completed)); else average=$(interop_initial_leg_seconds); fi; current_left=$$((role_average - leg_elapsed)); [ $$current_left -gt 0 ] || current_left=0; eta=$$((current_left + average * (total - index))); eta=$$(fmt $$eta); \
	      latest=$$(grep -E '^(PHASE |CHECK |baseline=|READY |Activated |Sending |Success rate|--- PASS|error:)' $$log | tail -1 || true); \
	      if [ "$(DEBUG)" = 1 ] && [ -d $(net_name) ]; then for live_log in $$(find $(net_name) -type f -name '*.log' | sort); do printf 'LOG %s\n' "$$live_log"; tail -n 3 "$$live_log"; done; fi; \
	      printf 'WAIT %02d/%02d %-9s %-12s leg=%s elapsed=%s eta=%s %s\n' $$index $$total $$baseline $$role $$(fmt $$leg_elapsed) $$(fmt $$overall) $$eta "$$latest"; done) & monitor=$$!; \
	    if wait $$child; then result=PASS; \
	    else result=FAIL; failed=1; tail -20 $$log; $(interop_stop_make) --no-print-directory interop-stop >/dev/null 2>&1 || true; fi; \
	    kill $$monitor 2>/dev/null || true; wait $$monitor 2>/dev/null || true; [ -z "$$debug_tail" ] || { kill $$debug_tail 2>/dev/null || true; wait $$debug_tail 2>/dev/null || true; }; child=''; monitor=''; debug_tail=''; \
	    duration=$$(($$(date +%s) - started)); completed=$$((completed + 1)); completed_seconds=$$((completed_seconds + duration)); \
	    eval role_total_$$role=$$((role_total + duration)); eval role_done_$$role=$$((role_done + 1)); \
	    eta=$$((completed_seconds / completed * (total - completed))); overall=$$(($$(date +%s) - matrix_started)); \
	    printf '%s\t%s\t%s\t%s\t%s\n' $$baseline $$role $$result $$duration $$log >> $(interop_report_dir)/report.tsv; \
	    printf '%-4s %02d/%02d %-9s %-12s leg=%s elapsed=%s eta=%s\n' $$result $$index $$total $$baseline $$role $$(fmt $$duration) $$(fmt $$overall) $$(fmt $$eta); \
	  done; \
	  $(interop_submake) --no-print-directory interop-report; exit $$failed

# Print the recorded revisions and per-leg durations from the last run
# without re-running.
interop-report:
	@test -f $(interop_report_dir)/report.tsv || { echo "No interoperability report found; run make interop-test" >&2; exit 2; }
	@awk -F '\t' 'NR == 1 { print "REVISIONS"; next } { printf "  %-9s %-16s %s %s\n", $$1, $$2, $$3, $$4 }' $(interop_report_dir)/revisions.tsv
	@awk -F '\t' 'function fmt(s) { return sprintf("%02d:%02d:%02d", int(s / 3600), int(s / 60) % 60, s % 60) } BEGIN { printf "\n%-11s %-14s %-7s %-10s %s\n", "BASELINE", "ROLE", "RESULT", "DURATION", "LOG" } NR > 1 { printf "%-11s %-14s %-7s %-10s %s\n", $$1, $$2, $$3, fmt($$4), $$5; seconds += $$4; if ($$3 != "PASS") failed++ } END { printf "\n%d passed, %d failed, %s total\n", NR - 1 - failed, failed, fmt(seconds) }' $(interop_report_dir)/report.tsv
	@failures=$$(grep -h '^CHECK .* result=FAIL' $(interop_report_dir)/logs/*.log 2>/dev/null || true); [ -z "$$failures" ] || printf '\nFAILED CHECKS\n%s\n' "$$failures"

# Bring up each baseline network and check it end to end.
interop-test-baseline: interop-build
	@set -e; cleanup() { $(interop_stop_make) --no-print-directory interop-stop >/dev/null 2>&1 || true; }; \
	  trap cleanup EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; \
	  $(MAKE) -j1 BASELINE=$(BASELINE) CHECK_CLIENT_VERSION=$(BASELINE) interop-check; \
	  for role in $(interop_roles) quorums; do \
	    $(MAKE) -j1 BASELINE=$(BASELINE) ROLE=$$role REUSE_NETWORK=true interop-test-role; \
	  done

# Bring up a baseline and swap the given ROLE through every other version,
# checking each; skips unavailable baselines/roles.
interop-test-role: interop-build
	@case "$(ROLE)" in mix|gateway|servicenode|dirauth|replica|courier|http|client2|quorums) ;; *) echo "ROLE must be one of $(interop_roles) or quorums" >&2; exit 2;; esac
	@case "$(ROLE)" in quorums) ;; *) case " $(interop_versions) " in *" $(BASELINE) "*) ;; *) echo "PHASE baseline=$(BASELINE) role=$(ROLE) action=skip reason=no-non-rocksdb-release"; exit 0;; esac;; esac
	@set -e; cleanup() { [ "$(REUSE_NETWORK)" = true ] || $(interop_stop_make) --no-print-directory interop-stop >/dev/null 2>&1 || true; }; \
	  trap cleanup EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; \
	  if [ "$(ROLE)" = quorums ]; then $(MAKE) -j1 BASELINE=$(BASELINE) REUSE_NETWORK=$(REUSE_NETWORK) interop-test-quorums; exit; fi; \
	  expected=$$(cat $(interop_dir)/$(BASELINE)/artifact); started=false; \
	  if [ -f $(net_name)/running.stamp ] && $(docker) network inspect $(compose_network_name) >/dev/null 2>&1 && grep -q "^$(BASELINE)[[:space:]]$$expected[[:space:]]" $(net_name)/runtime-baseline.tsv 2>/dev/null; then echo "PHASE baseline=$(BASELINE) role=$(ROLE) action=reuse-network"; \
	  else $(MAKE) --no-print-directory interop-stop >/dev/null 2>&1 || true; $(MAKE) -j1 BASELINE=$(BASELINE) interop-start; started=true; fi; \
	  case "$(ROLE)" in mix) services='$(interop_services_mix)';; gateway) services='$(interop_services_gateway)';; servicenode) services='$(interop_services_servicenode)';; dirauth) services='$(interop_services_dirauth)';; replica) services='$(interop_services_replica)';; courier) services='$(interop_services_courier)';; http) services='$(interop_services_http)';; client2) services='$(interop_services_client2)';; esac; \
	  failed=0; \
	  if [ "$$started" = true ]; then \
	    echo "PHASE baseline=$(BASELINE) role=$(ROLE) component=$(BASELINE) action=check-baseline"; \
	    if $(MAKE) -j1 BASELINE=$(BASELINE) COMPONENT_VERSION=$(BASELINE) ROLE=$(ROLE) EXPECT_AUTHS="$$services" interop-check-role; then \
	      echo "CHECK baseline=$(BASELINE) role=$(ROLE) component=$(BASELINE) service=all result=PASS"; \
	    else echo "CHECK baseline=$(BASELINE) role=$(ROLE) component=$(BASELINE) service=all result=FAIL"; exit 1; fi; \
	  fi; \
	  for component in $(interop_versions); do \
	    [ "$$component" = "$(BASELINE)" ] && continue; \
	    for service in $$services; do \
	      wait_after=$$(cat $(net_name)/interop.last_epoch 2>/dev/null || true); \
	      echo "PHASE baseline=$(BASELINE) role=$(ROLE) component=$$component service=$$service action=activate"; \
	      swapped=0; \
	      if $(MAKE) -j1 BASELINE=$(BASELINE) COMPONENT_VERSION=$$component SERVICE=$$service interop_check_target=interop-noop interop-swap-$(ROLE); then swapped=1; \
	      else failed=1; fi; \
	      result=FAIL; \
	      if [ $$swapped -eq 1 ] && $(MAKE) -j1 BASELINE=$(BASELINE) COMPONENT_VERSION=$$component ROLE=$(ROLE) WAIT_AFTER_EPOCH=$$wait_after EXPECT_AUTHS="$$service" interop-check-role; then result=PASS; \
	      else failed=1; fi; \
	      echo "CHECK baseline=$(BASELINE) role=$(ROLE) component=$$component service=$$service result=$$result"; \
	      echo "PHASE baseline=$(BASELINE) role=$(ROLE) component=$$component service=$$service action=restore"; \
	      if ! $(MAKE) -j1 BASELINE=$(BASELINE) ROLE=$(ROLE) SERVICE=$$service interop-restore-role; then exit 1; fi; \
	    done; \
	  done; \
	  exit $$failed

# Run a network whose services are a mix of versions and check it end to
# end.
interop-test-mixed-network: interop-build
	@set -e; cleanup() { $(interop_stop_make) --no-print-directory interop-stop >/dev/null 2>&1 || true; }; \
	  trap cleanup EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; \
	  $(MAKE) -j1 BASELINE=candidate interop-activate; \
	  for spec in \
	    'mix mix2 current' 'mix mix3 previous' \
	    'servicenode servicenode2 current' 'servicenode servicenode3 previous' \
	    'dirauth auth2 current' 'dirauth auth3 previous' \
	    'replica replica2 current' 'replica replica3 previous' 'replica replica5 current' \
	    'courier servicenode1 previous' 'courier servicenode2 current' \
	    'http servicenode1 current' 'http servicenode3 previous'; do \
	    set -- $$spec; role=$$1; service=$$2; component=$$3; \
	    echo "PHASE baseline=candidate role=$$role component=$$component service=$$service action=activate-all-version"; \
	    $(MAKE) -j1 BASELINE=candidate ROLE=$$role COMPONENT_VERSION=$$component SERVICE=$$service SWAP_RUNNING=false interop_check_target=interop-noop interop-swap-$$role; \
	  done; \
	  cd $(net_name) && $(docker_compose) up --remove-orphans --force-recreate -d; cd ..; touch $(net_name)/running.stamp; \
	  echo 'PHASE baseline=candidate role=mixed-network check=all-version-network'; \
	  if $(MAKE) -j1 BASELINE=candidate CHECK_CLIENT_VERSION=candidate CHECK_HTTP_VERSION=previous EXPECT_AUTHS='auth1 auth2 auth3' interop-check; then \
	    echo 'CHECK baseline=candidate role=mixed-network component=all service=all result=PASS'; \
	  else echo 'CHECK baseline=candidate role=mixed-network component=all service=all result=FAIL'; exit 1; fi

# Swap the dirauth/replica quorum to mixed versions in both orderings and
# check each; skipped unless two non-baseline versions exist.
interop-test-quorums: interop-build
	@n=$$(echo $(filter-out $(BASELINE),$(interop_versions)) | wc -w); [ "$$n" -ge 2 ] || { echo "PHASE baseline=$(BASELINE) role=quorums action=skip reason=needs-2-non-baseline-versions-have-$$n"; exit 0; }
	@set -e; cleanup() { [ "$(REUSE_NETWORK)" = true ] || $(interop_stop_make) --no-print-directory interop-stop >/dev/null 2>&1 || true; }; \
	  trap cleanup EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; \
	  expected=$$(cat $(interop_dir)/$(BASELINE)/artifact); \
	  if [ -f $(net_name)/running.stamp ] && $(docker) network inspect $(compose_network_name) >/dev/null 2>&1 && grep -q "^$(BASELINE)[[:space:]]$$expected[[:space:]]" $(net_name)/runtime-baseline.tsv 2>/dev/null; then echo "PHASE baseline=$(BASELINE) role=quorums action=reuse-network"; \
	  else $(MAKE) --no-print-directory interop-stop >/dev/null 2>&1 || true; $(MAKE) -j1 BASELINE=$(BASELINE) interop-start; fi; \
	  wait_after=$$(cat $(net_name)/interop.last_epoch 2>/dev/null || true); \
	  others=''; for version in $(interop_versions); do [ "$$version" = "$(BASELINE)" ] || others="$$others $$version"; done; \
	  set -- $$others; first=$$1; second=$$2; \
	  for order in "$$first $$second" "$$second $$first"; do \
	    set -- $$order; one=$$1; two=$$2; echo "PHASE baseline=$(BASELINE) role=quorums assignment=$$one,$$two"; \
	    for spec in "auth2 dirauth $$one" "auth3 dirauth $$two" \
	                "replica2 replica $$one" "replica3 replica $$two" \
	                "replica4 replica $$one" "replica5 replica $$two"; do \
	      set -- $$spec; service=$$1; bin=$$2; version=$$3; artifact=$$(cat $(interop_dir)/$$version/artifact); \
	      commit=$$(cat $(interop_dir)/$$version/commit); log="$(net_name)/$$service/katzenpost.log"; \
	      before=$$(grep -c " rev $$commit" "$$log" 2>/dev/null || true); \
	      cd "$(net_name)" && $(docker_compose) stop "$$service"; cd ..; \
	      install -m 0755 "$(interop_dir)/$$version/$$bin.$(distro).$$artifact" "$(net_name)/$$bin.$(distro).$$service.new"; \
	      mv -f "$(net_name)/$$bin.$(distro).$$service.new" "$(net_name)/$$bin.$(distro).$$service"; \
	      cd "$(net_name)" && $(docker_compose) start "$$service"; cd ..; \
	      ok=false; for i in $$(seq 1 30); do if [ "$$(grep -c " rev $$commit" "$$log" 2>/dev/null || true)" -gt "$${before:-0}" ]; then ok=true; break; fi; sleep 2; done; \
	      [ "$$ok" = true ] || { echo "quorum swap verify: $$service did not come up running rev $$commit" >&2; exit 1; }; \
	      $(MAKE) --no-print-directory SERVICE=$$service ROLE=$$bin BINS="$$bin" VERSION=$$version interop-record-artifact; \
	    done; \
	    $(MAKE) -j1 net_name=$(interop_net_name) WAIT_AFTER_EPOCH=$$wait_after EXPECT_AUTHS="auth1 auth2 auth3" CHECK_CLIENT_VERSION=$(BASELINE) $(interop_check_target); \
	    wait_after=$$(cat $(net_name)/interop.last_epoch); \
	  done

# Stop and remove the interop network's containers.
interop-stop:
	-@$(docker) rm -f katzenpost_interop_probe katzenpost_interop_ping katzenpost_interop_http >/dev/null 2>&1
	-@$(MAKE) --no-print-directory net_name=$(interop_net_name) stop >/dev/null 2>&1
	@rm -f $(net_name)/running.stamp $(net_name)/servicenode*/courier/*.socket

# Stop the network and remove its generated network directory.
interop-clean: interop-stop
	git clean -fdx $(net_name)
	@echo "Retained versioned builds in $(interop_dir)"

# Show what interop-clean would remove without removing it.
interop-clean-dryrun:
	git clean -ndx $(net_name)

# Remove the cached interop build artifacts.
interop-clean-cache:
	git clean -fdx $(interop_dir)

# Remove the interop-results report directory.
interop-clean-results:
	git clean -fdx $(interop_report_dir)

# Remove the obsolete standalone interop image and container left by older
# checkouts; the suite now runs in the base image, so this is a no-op once
# that image is gone.
interop-clean-image:
	-$(MAKE) clean-container-$(distro)_interop
	-$(MAKE) clean-image-$(distro)_interop

# Run interop-clean plus the cache, results, and image cleanups.
interop-clean-all: interop-clean interop-clean-cache interop-clean-results interop-clean-image

# clean-images must remove images and stamps for every distro a user could
# have named, not just the ones in DISTROS. Discover them from the on-disk
# stamps and per-distro cache dirs, union with DISTROS, and remove both the
# _base and _rust image/stamp. An interrupted `make -j test-distros` may
# also leave orphan containers behind, so sweep those too.
STAMP_DISTROS=$(sort $(patsubst %_base.stamp,%,$(wildcard *_base.stamp)) $(patsubst %_go_mod.stamp,%,$(wildcard *_go_mod.stamp)) $(patsubst %_rust.stamp,%,$(wildcard *_rust.stamp)))
CACHE_DISTROS=$(sort $(patsubst cache/go-build-%,%,$(wildcard cache/go-build-*)) $(patsubst cache/cargo-home-%,%,$(wildcard cache/cargo-home-*)) $(patsubst cache/cargo-target-%,%,$(wildcard cache/cargo-target-*)))
KNOWN_DISTROS=$(sort $(DISTROS) $(STAMP_DISTROS) $(CACHE_DISTROS))

clean-images: stop
	@-for distro in $(KNOWN_DISTROS); do \
		$(MAKE) distro=$$distro clean-container-$${distro}_base; \
		$(MAKE) distro=$$distro clean-image-$${distro}_base; \
		$(MAKE) distro=$$distro clean-image-$${distro}_rust; \
		$(MAKE) distro=$$distro clean-image-$${distro}_interop; \
	done
	-$(docker) ps -a --format '{{.Names}}' | grep -E '^(katzenpost_|mixnet-)' | xargs -r $(docker) rm -f

clean-container-%:
	-@$(docker) stop $(i_if_podman) $(patsubst clean-container-%,katzenpost_%,$@)
	-@$(docker) rm   $(i_if_podman) $(patsubst clean-container-%,katzenpost_%,$@)

clean-image-%:
	-$(docker) rmi $(patsubst clean-image-%,katzenpost-%,$@)
	-rm -fv $(patsubst clean-image-%,%,$@).stamp

# Stop every network, one per distro inferred from the on-disk build
# stamps, so `make clean` tears down everything even when the last-used
# distro differs. `make distro=foo stop` still stops only foo's network;
# `stop`'s `[ -e $(net_name) ]` guard makes this a no-op for any distro
# that was never started.
stop-all:
	@for d in $(STAMP_DISTROS); do $(MAKE) distro=$$d stop; $(MAKE) distro=$$d interop-stop; done

# Wipe the network directory of every distro ever built (stamp-inferred).
# Called by `clean` only; clean-local deliberately touches just the current
# net_name. `git clean` exits 0 even for a pathspec that matches nothing.
clean-testnets:
	@for d in $(STAMP_DISTROS); do git clean -fdx mixnet-$$d interop-$$d; done

clean-bin: stop
	rm -vf ./$(net_name)/*.$(distro)

# Light clean for the iteration loop: tear down the current testnet and
# wipe its state, but keep the go module/build cache. The cgo components
# (highctidh) are slow to rebuild, so use this between most iterations and
# reserve `clean` for full from-scratch verification. Only affects the
# current net_name/distro; the compiled binaries are wiped by the git
# clean, so this depends on `stop` (not `clean-bin`) to avoid a redundant
# rm.
clean-local: stop
	rm -f .base_port_seed
	git clean -f -x $(net_name)
	git status .

clean-local-dryrun:
	git clean -n -x $(net_name)

clean: stop-all
	$(MAKE) clean-local
	$(MAKE) clean-testnets
	# Legacy: keep removing the pre-mixnet-* default network directory
	# until leftover checkouts and stale config symlinks no longer matter.
	# It is no longer gitignored, so -d is required to remove it as a
	# plain untracked directory.
	git clean -fdx voting_mixnet
	$(MAKE) clean-images
	# The go module cache is intentionally written read-only (dirs 0555,
	# files 0444), so only a root-capable process can wipe it: even the
	# owning host user cannot delete files inside read-only directories.
	# Run the wipe in a throwaway alpine container (rootless podman maps
	# its uid 0 to the invoking user with full capabilities in-namespace).
	$(docker) run --rm -v $(shell readlink -f .)/$(cache_dir):/cache docker.io/alpine:latest sh -c 'rm -rfv /cache/*'
	-$(docker) ps -a|grep katzenpost|cat
	-$(docker) images|grep katzenpost|cat

run-ping: $(net_name)/ping.$(distro) $(net_name)/running.stamp | $(cache_dir)
	FORCE_COLOR=1 TERM=xterm-256color COLORTERM=truecolor $(docker) run --network=host -it -e FORCE_COLOR=1 -e TERM=xterm-256color -e COLORTERM=truecolor -e CLICOLOR_FORCE=1 ${docker_args} $(mount_net_name) --rm  katzenpost-$(distro)_base \
        /$(net_name)/ping.$(distro) --thin -c /$(net_name)/client/thinclient.toml -s echo --print-diff -n $(npings)

# parallel-load knobs. Override on the make command line:
#   make run-parallel-load clients=8 duration=5m
#   make run-parallel-load sweep=1,2,4,8,16 step=90s
clients?=4
duration?=5m
sweep?=
step?=90s
payload?=256
parallel_load_metrics_port?=9101
run-parallel-load: $(net_name)/parallel-load.$(distro) $(net_name)/running.stamp | $(cache_dir)
	$(docker) run --network=host --name katzenpost_parallel_load --hostname parallel-load ${docker_args} $(mount_net_name) --rm  katzenpost-$(distro)_base \
        /$(net_name)/parallel-load.$(distro) \
            -config /$(net_name)/client/thinclient.toml \
            -clients $(clients) -duration $(duration) -sweep "$(sweep)" -step $(step) \
            -payload-bytes $(payload) -metrics 0.0.0.0:$(parallel_load_metrics_port)

# cp-bench knobs. Override on the make command line:
#   make run-cp-bench cp_payload=65536
#   make run-cp-bench cp_sweep=4096,16384,65536,262144
cp_payload?=4096
cp_sweep?=
cp_propagation?=30s
cp_metrics_port?=9102
run-cp-bench: $(net_name)/cp-bench.$(distro) $(net_name)/running.stamp | $(cache_dir)
	$(docker) run --network=host --name katzenpost_cp_bench --hostname cp-bench ${docker_args} $(mount_net_name) --rm  katzenpost-$(distro)_base \
        /$(net_name)/cp-bench.$(distro) \
            -config /$(net_name)/client/thinclient.toml \
            -payload $(cp_payload) -sweep "$(cp_sweep)" -propagation $(cp_propagation) \
            -metrics 0.0.0.0:$(cp_metrics_port)

# Run the replica unit tests in a container, using the same invocation as
# .github/workflows/replica-tests.yml. The tests link highctidh's CTIDH
# implementation, which needs a large stack; the production binaries get it
# from -Wl,-z,stack-size in the ldflags variable above, and the test binary
# needs the same. (On glibc the default cgo thread stack happens to be big
# enough, which is why this only bites in the musl container image.)
# Override REPLICA_TEST_GORACE, REPLICA_TEST_LDFLAGS or REPLICA_TEST_FLAGS on
# the make command line to tweak the run
# (e.g. REPLICA_TEST_FLAGS="-race -v -run TestMigrate").
REPLICA_TEST_GORACE?=history_size=7
REPLICA_TEST_LDFLAGS?=-extldflags=-Wl,-z,stack-size=0x1F40000
REPLICA_TEST_FLAGS?=-coverprofile=coverage.out -race -v -failfast -timeout 30m
replica-test: $(distro)_base.stamp | $(net_name) $(cache_dir)
	$(docker) run --network=host ${docker_args} $(mount_net_name) --rm katzenpost-$(distro)_base \
		$(sh) -c 'cd /go/katzenpost/replica && GORACE=$(REPLICA_TEST_GORACE) go test -ldflags "$(REPLICA_TEST_LDFLAGS)" $(REPLICA_TEST_FLAGS) ./...'

# ---------------------------------------------------------------------
# thin_client / pigeonhole-cp (rust). These targets are the only ones
# that touch the thin_client checkout; `start`/`wait` and everything
# else stay rust-free, so katzenqt and thin_client CI calling
# `make start wait` never pay for the rust toolchain.
#
# thin-client-sync clones github.com/katzenpost/thin_client at
# thin_client_ref into docker/thin_client (gitignored). It refuses to
# touch an overridden thin_client_dir (dev checkouts, and thin_client's
# own CI pointing at the checkout under test). The fetch is best-effort
# so an already-synced offline checkout still builds.
thin-client-sync:
	@if [ "$(thin_client_dir)" != "thin_client" ]; then \
		echo "thin_client_dir=$(thin_client_dir) is overridden; thin-client-sync skipped (will not touch your checkout)."; \
	elif [ -d thin_client/.git ]; then \
		git -C thin_client fetch --tags --depth 1 origin || true; \
		git -C thin_client checkout $(thin_client_ref); \
	else \
		git clone --depth 1 --branch $(thin_client_ref) https://github.com/katzenpost/thin_client.git thin_client; \
	fi

# Build the pigeonhole-cp binary with cargo inside the rust image and
# copy it into $(net_name)/pigeonhole-cp.$(distro), mirroring the naming
# of the go binaries. thin-client-sync is a phony prerequisite on
# purpose: cargo is incremental, so an unchanged source tree is a fast
# no-op, and the copy always picks up whatever cargo produced.
$(net_name)/pigeonhole-cp.$(distro): $(distro)_rust.stamp thin-client-sync | $(net_name) $(cache_dir)
	@if [ ! -f $(thin_client_dir)/Cargo.toml ]; then \
		echo "error: no Cargo.toml at $(thin_client_dir). Set thin_client_dir to a thin_client checkout or run 'make thin-client-sync'."; exit 1; \
	fi
	$(docker) run --rm ${docker_args} ${thin_client_mount} \
		-v $(shell readlink -f .)/$(cargo_home):/cargo-home \
		-v $(shell readlink -f .)/$(cargo_target):/cargo-target \
		-e CARGO_HOME=/cargo-home \
		katzenpost-$(distro)_rust \
		bash -c "cd /go/thin_client && cargo build --release --bin pigeonhole-cp --features cli --target-dir /cargo-target"
	cp $(cargo_target)/release/pigeonhole-cp $@
	@echo "pigeonhole-cp built at $@"

# Generate a fresh Pigeonhole channel keypair. Prints the read/write
# capabilities and first index; wire them into the send/receive
# targets' variables.
pigeonhole-cp-genkey: $(net_name)/pigeonhole-cp.$(distro)
	$(docker) run --network=host --rm $(mount_net_name) katzenpost-$(distro)_base \
		/$(net_name)/pigeonhole-cp.$(distro) genkey -c /$(net_name)/client/thinclient.toml

# End-to-end round-trip of a random $(roundtrip_size)-byte file through a
# pigeonhole channel, using the pigeonhole_cp_roundtrip.sh wrapper, the
# make-built binary, and the generated config (whose dial address carries
# the configured base_port band). Runs on --network=host inside the base image
# so the binary's C library always matches, whatever the distro.
pigeonhole-cp-roundtrip: $(net_name)/pigeonhole-cp.$(distro)
	$(docker) run --network=host --rm ${docker_args} $(mount_net_name) katzenpost-$(distro)_base \
		$(sh) -c '/go/katzenpost/tools/chaos/scripts/pigeonhole_cp_roundtrip.sh -s $(roundtrip_size) /$(net_name)/client/thinclient.toml /$(net_name)/pigeonhole-cp.$(distro)'

shell: $(distro)_base.stamp | $(net_name) $(cache_dir)
	$(docker) run --network=host ${docker_args} $(mount_net_name) -w /go/katzenpost/docker/$(net_name) --rm -it katzenpost-$(distro)_base $(sh)

# this is for running with docker, where we are root outside and (except for
# here) non-root inside. When using podman, we are rootless outside and uid 0
# inside already, so this target is never needed.
rootshell: $(distro)_base.stamp
	$(docker) run --network=host --user 0:0 -v $(shell readlink -f ..):/go/katzenpost --rm -it katzenpost-$(distro)_base $(sh)

# test runs every component's docker-based integration tests against the
# running network. Only ./client defines docker tests today (memspool,
# catshadow, stream and bench, the other historical owners of such
# targets, are gone). Every client target below was probed against a
# healthy mixnet-alpine and passes; if a target starts failing it is NOT
# fixed here - it is dropped and the failure documented above the
# exclusion so `make test` stays green by construction.
#
# Probe status (August 2026):
#   dockertest-all     PASS  TestLegacyTests plus the new pigeonhole,
#                            multichannel, tombstone, copy-command and
#                            FromPayload tests - the same set CI runs via
#                            docker-mixnet.yml.
#   dockertest_pki_raw PASS  TestGetPKIDocumentRaw{,CurrentEpoch,UnknownEpoch}
#                            and TestGetDirectoryAuthorities.
test: wait
	$(MAKE) -C ../client testargs=$(testargs) dockertest-all
	$(MAKE) -C ../client testargs=$(testargs) dockertest_pki_raw

# Bring the testnet up on every supported distro (uses the shared build
# cache). Serial by default; with `make -j N test-distros` each
# test-distro-<distro> leg runs concurrently on its own mixnet-<distro>
# network and base_port band derived from the DISTROS order, so legs never
# share state. Each leg runs run-ping, which exits non-zero unless every
# ping is answered, so a leg's exit code asserts a healthy network. Legs
# deliberately leave their networks running; tear everything down with
# `make clean` (or one `make distro=<d> stop` per network).
DISTRO_PORTS=$(foreach d,$(DISTROS),$(d):$(shell set -- $(DISTROS); i=0; for x; do [ "$$x" = "$(d)" ] && printf '%s' $$((30000 + i * 10000)) && break; i=$$((i+1)); done))

# Each leg's sub-make runs with -j1 so its start/wait/run-ping goals
# stay ordered even when this file is built with -j from a parent make.
.PHONY: test-distro-%
test-distro-%:
	$(MAKE) -j1 distro=$* base_port=$(patsubst $*:%,%,$(filter $*:%,$(DISTRO_PORTS))) start wait run-ping

test-distros: $(addprefix test-distro-,$(DISTROS))

check-go-version:
	$(docker) run --rm katzenpost-$(distro)_base go version
