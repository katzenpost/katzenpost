.PHONY: clean clean-local clean-local-dryrun stop-all clean-testnets clean-image-% clean-container-% clean-images test test-distros test-distro-% rootshell shell run-ping go-mod-tidy go-mod-upgrade help start stop client-restart clean-client client-logs courier-restart servicenode-restart replica-restart config-only watch-replicas watch-auth watch-mixes watch-courier watch-servicenode watch-gateway watch-all-separate start-with-client-metrics print-url-grafana print-url-prometheus pumba-latency pumba-loss pumba-corrupt pumba-pause pumba-status pumba-stop selfcheck-cache-restore thin-client-sync pigeonhole-cp-genkey pigeonhole-cp-roundtrip

help:
	@echo "These make targets allow you to control the test network:"
	@echo " config-only        - generate configuration files only (no docker containers)"
	@echo " start              - start the testnet"
	@echo " stop               - stop the testnet"
	@echo " client-restart     - restart just the kpclientd daemon"
	@echo " client-logs        - view kpclientd daemon logs"
	@echo " courier-restart    - restart courier plugin via thwack interface"
	@echo " servicenode-restart - restart servicenode container (heavier)"
	@echo " replica-restart    - rebuild replica binary and restart all replica containers"
	@echo " wait               - wait until every node reports ready against the current consensus"
	@echo " watch              - tail -F all logs"
	@echo " watch-replicas     - monitor all replica logs"
	@echo " watch-auth         - monitor all directory authority logs"
	@echo " watch-mixes        - monitor all mix node logs"
	@echo " watch-courier      - monitor courier service log"
	@echo " watch-servicenode  - monitor service node log"
	@echo " watch-gateway      - monitor gateway log"
	@echo " watch-all-separate - monitor all logs with component labels"
	@echo " start-with-client-metrics - start with prometheus + grafana and kpclientd metrics"
	@echo " print-url-grafana  - print the Grafana URL"
	@echo " print-url-prometheus - print the Prometheus URL"
	@echo " pumba-latency      - induce network delay/jitter on mixnet containers (see pumba_* vars)"
	@echo " pumba-loss         - induce packet loss on mixnet containers (see pumba_* vars)"
	@echo " pumba-corrupt      - induce single-bit packet corruption (see pumba_corrupt_pct)"
	@echo " pumba-pause        - freeze a single container for pumba_pause_duration"
	@echo " pumba-status       - show all running pumba chaos containers"
	@echo " pumba-stop         - stop every katzenpost_pumba_* chaos container"
	@echo " status             - show testnet consensus status"
	@echo " show-latest-vote   - does what it says"
	@echo " thin-client-sync   - clone/update docker/thin_client at thin_client_ref"
	@echo " \$(net_name)/pigeonhole-cp.\$(distro) - build pigeonhole-cp (rust) into \$(net_name)/"
	@echo " pigeonhole-cp-genkey - print a fresh pigeonhole channel keypair"
	@echo " pigeonhole-cp-roundtrip - round-trip a file through a pigeonhole channel"
	@echo " run-ping           - send a ping over the testnet"
	@echo " test               - run every component's docker integration tests (requires the testnet to be up)"
	@echo " clean-bin          - stop, and delete compiled binaries"
	@echo " clean-local        - stop the current network, and wipe its state (keeps the build cache)"
	@echo " clean-local-dryrun - show what clean-local would delete"
	@echo " stop-all           - stop every network, one per distro inferred from build stamps"
	@echo " clean              - stop all networks, wipe all state, plus base images and the build cache"
	@echo " test-distros       - bring up and ping the testnet on every DISTRO, leaving them running (serial, or parallel with make -j)"
	@echo

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
base_port=30000
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
export docker docker_user docker_args distro sh warped net_name cache_dir mount_net_name
export no_decoy no_client_decoy no_courier_replica_decoy no_mixdecoy no_gatewaydecoy
export no_metrics pyroscope_dirauth pyroscope_kpclientd kpclientd_metrics
export wirekem nike kem mixes auths gateways serviceNodes storageNodes
export mu lP lL lM lR UserForwardPayloadLength log_level
export kpclientd_build_tags kpclientd_tags_flag pyroscope_dirauth_tags pyroscope_kpclientd_tags

docker_run_sh=$(docker) run ${docker_args} $(mount_net_name) --rm katzenpost-$(distro)_base $(sh) -c

testnet_binaries: $(net_name)/server.$(distro) $(net_name)/proxy_server.$(distro) $(net_name)/proxy_client.$(distro) $(net_name)/echo_server.$(distro) $(net_name)/dirauth.$(distro) $(net_name)/replica.$(distro) $(net_name)/courier.$(distro) $(net_name)/kpclientd.$(distro) | $(net_name) $(cache_dir)

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

start: $(docker_compose_yml) testnet_binaries selfcheck-cache-restore
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

servicenode-restart:
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

wait: $(net_name)/running.stamp $(net_name)/client/thinclient-bridge.toml | $(cache_dir)
	$(docker) run --network=$(net_name)_katzenpost-net ${docker_args} $(mount_net_name) --rm  katzenpost-$(distro)_base \
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
		$(docker_run_sh) 'cd cmd/dirauth && go build $(pyroscope_dirauth_tags) -trimpath -ldflags ${ldflags} -o /$(net_name)/dirauth.$(distro) && \
			cd ../fetch && go build -trimpath -ldflags ${ldflags} -o /$(net_name)/fetch.$(distro)'

$(net_name)/ping.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd cmd/ping && go mod verify && go build -ldflags ${ldflags} -o /$(net_name)/ping.$(distro)'

$(net_name)/parallel-load.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd tools/chaos/cmd/parallel-load && go build -ldflags ${ldflags} -o /$(net_name)/parallel-load.$(distro)'

$(net_name)/cp-bench.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd tools/chaos/cmd/cp-bench && go build -ldflags ${ldflags} -o /$(net_name)/cp-bench.$(distro)'

$(net_name)/kpclientd.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd cmd/kpclientd && go mod verify && go build $(kpclientd_tags_flag) -ldflags ${ldflags} -o /$(net_name)/kpclientd.$(distro)'

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
	@for d in $(STAMP_DISTROS); do $(MAKE) distro=$$d stop; done

# Wipe the network directory of every distro ever built (stamp-inferred).
# Called by `clean` only; clean-local deliberately touches just the current
# net_name. `git clean` exits 0 even for a pathspec that matches nothing.
clean-testnets:
	@for d in $(STAMP_DISTROS); do git clean -fdx mixnet-$$d; done

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
        /$(net_name)/ping.$(distro) --thin -c /$(net_name)/client/thinclient.toml -s echo --print-diff -n 10

# parallel-load knobs. Override on the make command line:
#   make run-parallel-load clients=8 duration=5m
#   make run-parallel-load sweep=1,2,4,8,16 step=90s
clients?=4
duration?=5m
sweep?=
step?=90s
payload?=256
parallel_load_metrics_port?=9101
run-parallel-load: $(net_name)/parallel-load.$(distro) $(net_name)/running.stamp $(net_name)/client/thinclient-bridge.toml | $(cache_dir)
	$(docker) run --network=$(net_name)_katzenpost-net --name katzenpost_parallel_load --hostname parallel-load ${docker_args} $(mount_net_name) --rm  katzenpost-$(distro)_base \
        /$(net_name)/parallel-load.$(distro) \
            -config /$(net_name)/client/thinclient-bridge.toml \
            -clients $(clients) -duration $(duration) -sweep "$(sweep)" -step $(step) \
            -payload-bytes $(payload) -metrics 0.0.0.0:$(parallel_load_metrics_port)

# Generate the bridge-network thinclient config the first time it is needed.
# The host-network thinclient.toml dials localhost:base_port+2000 (kpclientd
# is published on the host via the compose port forward); the bridge-network
# variant uses the compose service name kpclientd:64331 directly.
$(net_name)/client/thinclient-bridge.toml: | $(net_name)/client
	@echo '[Dial]'                                       >  $@
	@echo '  [Dial.Tcp]'                                 >> $@
	@echo '    Address = "kpclientd:64331"'              >> $@
	@echo '    Network = "tcp"'                          >> $@

# cp-bench knobs. Override on the make command line:
#   make run-cp-bench cp_payload=65536
#   make run-cp-bench cp_sweep=4096,16384,65536,262144
cp_payload?=4096
cp_sweep?=
cp_propagation?=30s
cp_metrics_port?=9102
run-cp-bench: $(net_name)/cp-bench.$(distro) $(net_name)/running.stamp $(net_name)/client/thinclient-bridge.toml | $(cache_dir)
	$(docker) run --network=$(net_name)_katzenpost-net --name katzenpost_cp_bench --hostname cp-bench ${docker_args} $(mount_net_name) --rm  katzenpost-$(distro)_base \
        /$(net_name)/cp-bench.$(distro) \
            -config /$(net_name)/client/thinclient-bridge.toml \
            -payload $(cp_payload) -sweep "$(cp_sweep)" -propagation $(cp_propagation) \
            -metrics 0.0.0.0:$(cp_metrics_port)

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
