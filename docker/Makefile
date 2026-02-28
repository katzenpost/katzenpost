.PHONY: clean clean-local clean-local-dryrun clean-image-% clean-container-% clean-images test rootshell shell run-ping go-mod-tidy go-mod-upgrade help start stop client-restart clean-client client-logs courier-restart servicenode-restart config-only watch-replicas watch-auth watch-mixes watch-courier watch-servicenode watch-gateway watch-all-separate

help:
	@echo "These make targets allow you to control the test network:"
	@echo " config-only        - generate configuration files only (no docker containers)"
	@echo " start              - start the testnet"
	@echo " stop               - stop the testnet"
	@echo " client-restart     - restart just the kpclientd daemon"
	@echo " client-logs        - view kpclientd daemon logs"
	@echo " courier-restart    - restart courier plugin via thwack interface"
	@echo " servicenode-restart - restart servicenode container (heavier)"
	@echo " wait               - wait for testnet to have consensus"
	@echo " watch              - tail -F all logs"
	@echo " watch-replicas     - monitor all replica logs"
	@echo " watch-auth         - monitor all directory authority logs"
	@echo " watch-mixes        - monitor all mix node logs"
	@echo " watch-courier      - monitor courier service log"
	@echo " watch-servicenode  - monitor service node log"
	@echo " watch-gateway      - monitor gateway log"
	@echo " watch-all-separate - monitor all logs with component labels"
	@echo " status             - show testnet consensus status"
	@echo " show-latest-vote   - does what it says"
	@echo " run-ping           - send a ping over the testnet"
	@echo " clean-bin          - stop, and delete compiled binaries"
	@echo " clean-local        - stop, and delete data and binaries"
	@echo " clean-local-dryrun - show what clean-local would delete"
	@echo " clean              - the above, plus cleans includes go_deps images"
	@echo

warped?=true
no_decoy?=false
no_mixdecoy?=true
mixes=3
auths=3
gateways=1
serviceNodes=3

# Parameters
sr=0
mu=0.005
muMax=1000
lP=0.001
lPMax=1000
lL=0.0005
lLMax=1000
lD=0.0005
lDMax=3000
lM=0.0005
lMMax=100
lGMax=1000

UserForwardPayloadLength=2000

# hybrid ctidh PQ can work here, but requires manually building ctidh.
nike=x25519

# kem can be Kyber1024-X448 or any of the other schemes at https://github.com/cloudflare/circl/blob/main/kem/schemes/schemes.go (and then nike must be unset)
kem=

DISTROS=alpine debian
distro=alpine
wirekem=xwing
net_name=voting_mixnet
base_port=30000
bind_addr=127.0.0.1
docker_compose_yml=$(net_name)/docker-compose.yml
sh=$(shell if echo ${distro}|grep -q alpine; then echo sh; else echo bash; fi)
cache_dir=cache

# no_decoy and no_mixdecoy control enabling dockerized mixnets with or without decoy traffic
ifeq ($(no_mixdecoy),true)
  noMixDecoy=--noMixDecoy
endif

ifeq ($(no_decoy),true)
  noDecoy=--noDecoy
endif

# log_level can be DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL
log_level=DEBUG

docker=$(shell if which podman|grep -q .; then echo podman; else echo docker; fi)

ldflags="-extldflags '-Wl,-z,stack-size=0x1F40000' -buildid= -X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped}"

uid?=$(shell [ "$$SUDO_UID" != "" ] && echo "$$SUDO_UID" || id -u)
gid?=$(shell [ "$$SUDO_GID" != "" ] && echo "$$SUDO_GID" || id -g)

docker_user?=$(shell if echo ${docker}|grep -q podman; then echo 0:0; else echo ${uid}:${gid}; fi)
docker_args=--user ${docker_user} --volume $(shell readlink -f ..):/go/katzenpost --workdir /go/katzenpost -v $(shell readlink -f .)/$(cache_dir)/go:/go/ -e GOCACHE=/go/cache

replace_name=$(shell if echo ${docker}|grep -q podman; then echo " --replace --name"; else echo " --name"; fi)
i_if_podman=$(shell if echo ${docker}|grep -q podman; then echo " -i"; else echo; fi)
mount_net_name=-v `pwd`/$(net_name):/$(net_name)

docker_compose_v1_or_v2?= $(shell [ -e /usr/libexec/docker/cli-plugins/docker-compose ] && echo /usr/libexec/docker/cli-plugins/docker-compose || echo docker-compose)
docker_compose?= DOCKER_USER=$(docker_user) $(shell if which podman|grep -q .; then echo DOCKER_HOST="unix://$$XDG_RUNTIME_DIR/podman/podman.sock" podman compose; else echo $(docker_compose_v1_or_v2); fi)

make_args=--no-print-directory net_name=$(net_name) docker=$(docker) distro=$(distro) warped=$(warped) docker_user=$(docker_user)

docker_run_sh=$(docker) run ${docker_args} $(mount_net_name) --rm katzenpost-$(distro)_base $(sh) -c

testnet_binaries: $(net_name)/server.$(distro) $(net_name)/proxy_server.$(distro) $(net_name)/proxy_client.$(distro) $(net_name)/echo_server.$(distro) $(net_name)/dirauth.$(distro) $(net_name)/replica.$(distro) $(net_name)/courier.$(distro) $(net_name)/kpclientd.$(distro) | $(net_name) $(cache_dir)

$(net_name):
	mkdir -vp $(net_name)

$(cache_dir): $(cache_dir)/go

$(cache_dir)/go:
	mkdir -vp $(cache_dir)/go

$(docker_compose_yml): ../cmd/genconfig/main.go $(distro)_base.stamp | $(net_name) $(cache_dir)
	$(docker) run ${docker_args} --rm katzenpost-$(distro)_base \
		$(sh) -c 'cd cmd/genconfig && go build && cd ../../docker \
		&& ../cmd/genconfig/genconfig --wirekem $(wirekem) --addr ${bind_addr} --nrVoting ${auths} --nodes ${mixes} --gateways ${gateways} \
		--serviceNodes ${serviceNodes} \
		--sendRate ${sr} --mu ${mu} --muMax ${muMax} --lambdaP ${lP} --lambdaPMax ${lPMax} --lambdaL ${lL} \
		--lambdaLMax ${lLMax} --lambdaD ${lD} --lambdaDMax ${lDMax} --lambdaM ${lM} --lambdaMMax ${lMMax} \
		--binSuffix .$(distro) --voting --outDir ./$(net_name) --baseDir /$(net_name) --port $(base_port) \
		--nike "$(nike)" --kem "$(kem)" --dockerImage katzenpost-$(distro)_base \
		${noMixDecoy} ${noDecoy} \
		--UserForwardPayloadLength $(UserForwardPayloadLength) --logLevel $(log_level)'

# Generate configuration files only (without docker containers)
# This is useful for tests that depend on config files existing (e.g., client2/testdata symlinks)
config-only: | $(net_name)
	@echo "Generating mixnet configuration files without docker containers..."
	cd ../cmd/genconfig && go build && ./genconfig --wirekem $(wirekem) --addr ${bind_addr} --nrVoting ${auths} --nodes ${mixes} --gateways ${gateways} \
		--serviceNodes ${serviceNodes} \
		--sendRate ${sr} --mu ${mu} --muMax ${muMax} --lambdaP ${lP} --lambdaPMax ${lPMax} --lambdaL ${lL} \
		--lambdaLMax ${lLMax} --lambdaD ${lD} --lambdaDMax ${lDMax} --lambdaM ${lM} --lambdaMMax ${lMMax} \
		--voting --outDir ../../docker/$(net_name) --baseDir /$(net_name) --port $(base_port) \
		--nike "$(nike)" --kem "$(kem)" \
		${noMixDecoy} ${noDecoy} \
		--UserForwardPayloadLength $(UserForwardPayloadLength) --logLevel $(log_level)
	@echo "Configuration files generated in ./$(net_name)/"
	@echo "Tests can now use the symlinked configs (e.g., client2/testdata/client.toml -> ../../docker/$(net_name)/client2/client.toml)"

$(net_name)/running.stamp:
	make $(make_args) start

start: $(docker_compose_yml) testnet_binaries
	cd $(net_name); $(docker_compose) up --remove-orphans -d; $(docker_compose) ps
	touch $(net_name)/running.stamp

start_debug: $(docker_compose_yml) testnet_binaries
	cd $(net_name); $(docker_compose) up --remove-orphans;
	touch $(net_name)/running.stamp

stop:
	[ -e $(net_name) ] && cd $(net_name) && $(docker_compose) down --remove-orphans; rm -fv running.stamp voting_mixnet/servicenode*/courier/*.socket

client-restart:
	@echo "Cleaning and rebuilding kpclientd daemon..."
	rm -fv $(net_name)/kpclientd.$(distro)
	make $(make_args) $(net_name)/kpclientd.$(distro)
	@echo "Restarting kpclientd daemon..."
	cd $(net_name) && $(docker_compose) stop kpclientd
	cd $(net_name) && $(docker_compose) up -d kpclientd
	@echo "kpclientd daemon restarted with updated code"

client-logs:
	@echo "Tailing kpclientd daemon logs (Ctrl+C to exit)..."
	cd $(net_name) && $(docker_compose) logs -f --tail 20 kpclientd

courier-restart:
	@echo "Stopping courier plugin via thwack management interface..."
	@cd $(net_name) && $(docker_compose) exec -T servicenode1 sh -c 'echo "STOP_KAETZCHEN courier" | /usr/bin/nc -U /voting_mixnet/servicenode1/management_sock' || true
	@sleep 1
	@echo "Cleaning and rebuilding courier binary..."
	rm -fv $(net_name)/courier.$(distro)
	make $(make_args) $(net_name)/courier.$(distro)
	@echo "Starting courier plugin via thwack management interface..."
	@cd $(net_name) && $(docker_compose) exec -T servicenode1 sh -c 'echo "START_KAETZCHEN courier" | /usr/bin/nc -U /voting_mixnet/servicenode1/management_sock'
	@echo "Courier service restarted with updated code"

servicenode-restart:
	@echo "Cleaning and rebuilding courier binary..."
	rm -fv $(net_name)/courier.$(distro)
	make $(make_args) $(net_name)/courier.$(distro)
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
	@grep -A30 'Ready to send' voting_mixnet/auth1/katzenpost.log |tail -30|sed /Sending/q

wait: $(net_name)/running.stamp | $(cache_dir)
	$(docker) run --network=host ${docker_args} $(mount_net_name) --rm  katzenpost-$(distro)_base \
	/$(net_name)/fetch.$(distro) -f /$(net_name)/client2/thinclient.toml

debian_base.stamp:
	$(docker) run $(replace_name) katzenpost_debian_base docker.io/golang:bullseye $(sh) -c "echo -e 'deb https://deb.debian.org/debian bullseye main\ndeb https://deb.debian.org/debian bullseye-updates main\ndeb https://deb.debian.org/debian-security bullseye-security main' > /etc/apt/sources.list && cat /etc/apt/sources.list && apt update && apt upgrade -y && apt install -y pv && adduser katzenpost --gecos '' --disabled-password && apt update && apt upgrade -y"
	$(docker) commit katzenpost_debian_base katzenpost-debian_base
	$(docker) rm katzenpost_debian_base
	touch $@

alpine_base.stamp:
	$(docker) run $(replace_name) katzenpost_alpine_base docker.io/alpine:20250108 sh -c '\
		adduser katzenpost --gecos "" --disabled-password && \
		apk update && apk upgrade && \
		apk add gcc musl-dev make pv rocksdb-dev g++ curl netcat-openbsd && \
		curl -fsSL https://go.dev/dl/go1.26.0.linux-amd64.tar.gz | tar -C /usr/local -xzf - && \
		ln -s /usr/local/go/bin/go /usr/bin/go && \
		ln -s /usr/local/go/bin/gofmt /usr/bin/gofmt' \
	&& $(docker) commit katzenpost_alpine_base katzenpost-alpine_base \
	&& $(docker) rm katzenpost_alpine_base
	touch $@

go-mod-tidy: $(distro)_base.stamp | $(net_name) $(cache_dir)
	$(docker) run ${docker_args} katzenpost-$(distro)_base \
			$(sh) -c "go mod tidy"

go-mod-upgrade: $(distro)_base.stamp | $(net_name) $(cache_dir)
	$(docker) run ${docker_args} katzenpost-$(distro)_base \
			$(sh) -c 'go get -d -u ./... && go mod tidy'

$(net_name)/server.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd cmd/server ; go build -trimpath -ldflags ${ldflags} && mv server /$(net_name)/server.$(distro)'

$(net_name)/courier.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd cmd/courier ; go build -trimpath -ldflags ${ldflags} && mv courier /$(net_name)/courier.$(distro)'

$(net_name)/replica.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd cmd/replica ; go build -trimpath -ldflags ${ldflags} && mv replica /$(net_name)/replica.$(distro)'

$(net_name)/proxy_client.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd cmd/http-proxy-client; go build -trimpath -ldflags ${ldflags} && mv http-proxy-client /$(net_name)/proxy_client.$(distro)'

$(net_name)/proxy_server.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd cmd/http-proxy-server; go build -trimpath -ldflags ${ldflags} && mv http-proxy-server /$(net_name)/proxy_server.$(distro)'

$(net_name)/echo_server.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd cmd/echo-plugin ; go build -trimpath -ldflags ${ldflags} && mv echo-plugin /$(net_name)/echo_server.$(distro)'

$(net_name)/dirauth.$(distro): $(distro)_base.stamp $(docker_compose_yml) | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd cmd/dirauth && go build -trimpath -ldflags ${ldflags} && mv dirauth /$(net_name)/dirauth.$(distro) && \
			cd ../fetch && go build -trimpath -ldflags ${ldflags} && mv fetch /$(net_name)/fetch.$(distro)'

$(net_name)/ping.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd cmd/ping && go mod verify && go build -ldflags ${ldflags} && \
			mv ping /$(net_name)/ping.$(distro)'

$(net_name)/kpclientd.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd cmd/kpclientd && go mod verify && go build -ldflags ${ldflags} && \
			mv kpclientd /$(net_name)/kpclientd.$(distro)'

clean-images: stop
	@-for distro in $(DISTROS); do \
		make $(make_args) distro=$$distro clean-container-$${distro}_base; \
		make $(make_args) distro=$$distro clean-image-$${distro}_base; \
	done \

clean-container-%:
	-@$(docker) stop $(i_if_podman) $(patsubst clean-container-%,katzenpost_%,$@)
	-@$(docker) rm   $(i_if_podman) $(patsubst clean-container-%,katzenpost_%,$@)

clean-image-%:
	-$(docker) rmi $(patsubst clean-image-%,katzenpost-%,$@)
	-rm -fv $(patsubst clean-image-%,%,$@).stamp

clean-bin: stop
	rm -vf ./$(net_name)/*.$(distro)

clean-local: clean-bin
	# Clean up replica data files (preserve .toml configs)
	rm -rfv $(net_name)/replica*/replica.db $(net_name)/replica*/*.log $(net_name)/replica*/link.*.pem
	# Clean up courier data files (preserve .toml configs)
	rm -rfv $(net_name)/servicenode*/courier/*.log $(net_name)/servicenode*/courier/*.db $(net_name)/servicenode*/courier/link.*.pem
	git clean -f -x $(net_name)
	git status .

clean-local-dryrun:
	git clean -n -x $(net_name)

clean: clean-images clean-local
	rm -rfv $(cache_dir)
	-$(docker) ps -a|grep katzenpost|cat
	-$(docker) images|grep katzenpost|cat

run-ping: $(net_name)/ping.$(distro) $(net_name)/running.stamp | $(cache_dir)
	FORCE_COLOR=1 TERM=xterm-256color COLORTERM=truecolor $(docker) run --network=host -it -e FORCE_COLOR=1 -e TERM=xterm-256color -e COLORTERM=truecolor -e CLICOLOR_FORCE=1 ${docker_args} $(mount_net_name) --rm  katzenpost-$(distro)_base \
        /$(net_name)/ping.$(distro) --thin -c /go/katzenpost/client2/testdata/thinclient.toml -s echo --print-diff -n 10

shell: $(distro)_base.stamp | $(net_name) $(cache_dir)
	$(docker) run --network=host ${docker_args} $(mount_net_name) -w /go/katzenpost/docker/$(net_name) --rm -it katzenpost-$(distro)_base $(sh)

# this is for running with docker, where we are root outside and (except for
# here) non-root inside. When using podman, we are rootless outside and uid 0
# inside already, so this target is never needed.
rootshell: $(distro)_base.stamp
	$(docker) run --network=host --user 0:0 -v $(shell readlink -f ..):/go/katzenpost --rm -it katzenpost-$(distro)_base $(sh)

test: wait
	cd ../client    && make $(make_args) testargs=$(testargs) dockerdockertest

check-go-version:
	podman run --rm katzenpost-alpine_base go version
