.PHONY: clean clean-local clean-local-dryrun clean-image-% clean-container-% clean-images test rootshell shell run-ping go-mod-tidy go-mod-upgrade help start stop

help:
	@echo "These make targets allow you to control the test network:"
	@echo " start              - start the testnet"
	@echo " stop               - stop the testnet"
	@echo " wait               - wait for testnet to have consensus"
	@echo " watch              - tail -F all logs"
	@echo " status             - show testnet consensus status"
	@echo " show-latest-vote   - does what it says"
	@echo " run-ping           - send a ping over the testnet"
	@echo " clean-bin          - stop, and delete compiled binaries"
	@echo " clean-local        - stop, and delete data and binaries"
	@echo " clean-local-dryrun - show what clean-local would delete"
	@echo " clean              - the above, plus cleans includes go_deps images"
	@echo

warped?=true
no_decoy?=true
no_mixdecoy?=true
mixes=3
auths=3
gateways=1
serviceNodes=1

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

# ratchetNike can be NOBS_CSIDH-X25519, "CTIDH511-X25519", "CTIDH512-X25519", "CTIDH1024-X25519", "CTIDH2048-X25519"
# and defaults to CTIDH512-X25519
ratchetNike?=CTIDH512-X25519

# kem can be Kyber1024-X448 or any of the other schemes at https://github.com/cloudflare/circl/blob/main/kem/schemes/schemes.go (and then nike must be unset)
kem=

DISTROS=alpine debian
distro=alpine
wirekem=xwing
replicanike=CTIDH1024-X25519
net_name=voting_mixnet
base_port=30000
bind_addr=127.0.0.1
docker_compose_yml=$(net_name)/docker-compose.yml
sh=$(shell if echo ${distro}|grep -q alpine; then echo sh; else echo bash; fi)
cache_dir=cache

# no_decoy and no_mixdecoy control enabling dockerized mixnets with or without decoy traffic
noMixDecoy=$(shell if [[ $no_mixdecoy ]]; then echo -noMixDecoy; fi)
noDecoy=$(shell if [[ $no_decoy ]]; then echo -noDecoy; fi)

# log_level can be DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL
log_level=INFO

no_decoy?=false
no_mixdecoy?=false

noDecoy=$(shell if [[ $no_decoy ]]; then echo -noDecoy; fi)
noMixDecoy=$(shell if [[ $no_mixdecoy ]]; then echo -noMixDecoy; fi)

docker=$(shell if which podman|grep -q .; then echo podman; else echo docker; fi)

ldflags="-extldflags '-Wl,-z,stack-size=0x1F40000' -buildid= -X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped}"

uid?=$(shell [ "$$SUDO_UID" != "" ] && echo "$$SUDO_UID" || id -u)
gid?=$(shell [ "$$SUDO_GID" != "" ] && echo "$$SUDO_GID" || id -g)

docker_user?=$(shell if echo ${docker}|grep -q podman; then echo 0:0; else echo ${uid}:${gid}; fi)
docker_args=--user ${docker_user} --volume $(shell readlink -f ..):/go/katzenpost --workdir /go/katzenpost -v $(shell readlink -f .)/$(cache_dir)/go:/go/ -e GOCACHE=/go/cache -e GOPATH=/go

replace_name=$(shell if echo ${docker}|grep -q podman; then echo " --replace --name"; else echo " --name"; fi)
i_if_podman=$(shell if echo ${docker}|grep -q podman; then echo " -i"; else echo; fi)
mount_net_name=-v `pwd`/$(net_name):/$(net_name)

docker_compose_v1_or_v2?= $(shell [ -e /usr/libexec/docker/cli-plugins/docker-compose ] && echo /usr/libexec/docker/cli-plugins/docker-compose || echo docker-compose)
docker_compose?= DOCKER_USER=$(docker_user) $(shell if which podman|grep -q .; then echo DOCKER_HOST="unix://$$XDG_RUNTIME_DIR/podman/podman.sock" $(docker_compose_v1_or_v2); else echo $(docker_compose_v1_or_v2); fi)

make_args=--no-print-directory net_name=$(net_name) docker=$(docker) distro=$(distro) warped=$(warped) docker_user=$(docker_user)

docker_run_sh=$(docker) run ${docker_args} $(mount_net_name) --rm katzenpost-$(distro)_base $(sh) -c

testnet_binaries: $(net_name)/server.$(distro) $(net_name)/proxy_server.$(distro) $(net_name)/proxy_client.$(distro) $(net_name)/memspool.$(distro) $(net_name)/pigeonhole.$(distro) $(net_name)/panda_server.$(distro) $(net_name)/echo_server.$(distro) $(net_name)/voting.$(distro) $(net_name)/replica.$(distro) | $(net_name) $(cache_dir)

$(net_name):
	mkdir -vp $(net_name)

$(cache_dir): $(cache_dir)/go

$(cache_dir)/go:
	mkdir -vp $(cache_dir)/go

$(docker_compose_yml): ../genconfig/main.go $(distro)_base.stamp | $(net_name) $(cache_dir)
	$(docker) run ${docker_args} --rm katzenpost-$(distro)_base \
		$(sh) -c 'cd genconfig && go build && cd ../docker \
		&& ../genconfig/genconfig -wirekem $(wirekem) -a ${bind_addr} -nv ${auths} -n ${mixes} -gateways ${gateways} \
		-serviceNodes ${serviceNodes} \
		-sr ${sr} -mu ${mu} -muMax ${muMax} -lP ${lP} -lPMax ${lPMax} -lL ${lL} \
		-lLMax ${lLMax} -lD ${lD} -lDMax ${lDMax} -lM ${lM} -lMMax ${lMMax} \
		-S .$(distro) -v -o ./$(net_name) -b /$(net_name) -P $(base_port) \
		-nike "$(nike)" -ratchetNike "$(ratchetNike)" -kem "$(kem)" -replicaNike "$(replicanike)" -d katzenpost-$(distro)_base \
		${noMixDecoy} ${noDecoy} \
		-UserForwardPayloadLength $(UserForwardPayloadLength) -log_level $(log_level)'

$(net_name)/running.stamp:
	make $(make_args) start

start: $(docker_compose_yml) testnet_binaries
	cd $(net_name); $(docker_compose) up --remove-orphans -d; $(docker_compose) top
	touch $(net_name)/running.stamp

start_debug: $(docker_compose_yml) testnet_binaries
	cd $(net_name); $(docker_compose) up --remove-orphans;
	touch $(net_name)/running.stamp

stop:
	[ -e $(net_name) ] && cd $(net_name) && $(docker_compose) down --remove-orphans; rm -fv running.stamp

watch:
	tail -F $(net_name)/*/*.log

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
	/$(net_name)/fetch.$(distro) -f /$(net_name)/client/client.toml

debian_base.stamp:
	$(docker) run $(replace_name) katzenpost_debian_base docker.io/golang:bullseye $(sh) -c "echo -e 'deb https://deb.debian.org/debian bullseye main\ndeb https://deb.debian.org/debian bullseye-updates main\ndeb https://deb.debian.org/debian-security bullseye-security main' > /etc/apt/sources.list && cat /etc/apt/sources.list && apt update && apt upgrade -y && apt install -y pv && adduser katzenpost --gecos '' --disabled-password && apt update && apt upgrade -y"
	$(docker) commit katzenpost_debian_base katzenpost-debian_base
	$(docker) rm katzenpost_debian_base
	touch $@

alpine_base.stamp:
	$(docker) run $(replace_name) katzenpost_alpine_base docker.io/alpine:edge sh -c 'adduser katzenpost --gecos "" --disabled-password  && apk update && apk upgrade && apk add go gcc musl-dev make pv rocksdb-dev g++ ' \
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
		$(docker_run_sh) 'cd server/cmd/server ; go build -trimpath -ldflags ${ldflags} && mv server /$(net_name)/server.$(distro)'

$(net_name)/replica.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd replica/cmd/replica ; go build -trimpath -ldflags ${ldflags} && mv replica /$(net_name)/replica.$(distro)'

$(net_name)/proxy_client.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd http/proxy/client; go build -trimpath -ldflags ${ldflags} && mv client /$(net_name)/proxy_client.$(distro)'

$(net_name)/proxy_server.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd http/proxy/server; go build -trimpath -ldflags ${ldflags} && mv server /$(net_name)/proxy_server.$(distro)'

$(net_name)/memspool.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd memspool/server/cmd/memspool ; go build -trimpath -ldflags ${ldflags} && mv memspool /$(net_name)/memspool.$(distro)'

$(net_name)/pigeonhole.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd pigeonhole/server/cmd/pigeonhole ; go build -trimpath -ldflags ${ldflags} && mv pigeonhole /$(net_name)/pigeonhole.$(distro)'

$(net_name)/panda_server.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd panda/server/cmd/panda_server ; go build -trimpath -ldflags ${ldflags} && mv panda_server /$(net_name)/panda_server.$(distro)'

$(net_name)/echo_server.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd server_plugins/cbor_plugins/echo-go ; go build -trimpath -ldflags ${ldflags} && mv echo-go /$(net_name)/echo_server.$(distro)'

$(net_name)/voting.$(distro): $(distro)_base.stamp $(docker_compose_yml) | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd authority && make $(make_args) cmd/voting/voting cmd/fetch/fetch && \
			mv cmd/voting/voting /$(net_name)/voting.$(distro) && \
			mv cmd/fetch/fetch /$(net_name)/fetch.$(distro)'

$(net_name)/ping.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker_run_sh) 'cd ping && go mod verify && go build -ldflags ${ldflags} && \
			mv ping /$(net_name)/ping.$(distro)'

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
	git clean -f -x $(net_name)
	git status .

clean-local-dryrun:
	git clean -n -x $(net_name)

clean: clean-images clean-local
	rm -rfv $(cache_dir)
	-$(docker) ps -a|grep katzenpost|cat
	-$(docker) images|grep katzenpost|cat

run-ping: $(net_name)/ping.$(distro) $(net_name)/running.stamp | $(cache_dir)
	$(docker) run --network=host ${docker_args} $(mount_net_name) --rm  katzenpost-$(distro)_base \
        /$(net_name)/ping.$(distro) -c /go/katzenpost/docker/$(net_name)/client/client.toml -s echo -printDiff -n 10

restart-memspool: $(net_name)/running.stamp stop-memspool start-memspool

stop-memspool:
	@echo STOP_KAETZCHEN spool|socat - unix:$(net_name)/servicenode1/management_sock|grep "250 spool" && echo stopped memspool || echo failed to stop memspool

start-memspool: $(net_name)/memspool.$(distro)
	@echo START_KAETZCHEN spool|socat - unix:$(net_name)/servicenode1/management_sock|grep "250 spool"
	@echo started memspool

shell: $(distro)_base.stamp | $(net_name) $(cache_dir)
	$(docker) run --network=host ${docker_args} $(mount_net_name) -w /go/katzenpost/docker/$(net_name) --rm -it katzenpost-$(distro)_base $(sh)

# this is for running with docker, where we are root outside and (except for
# here) non-root inside. When using podman, we are rootless outside and uid 0
# inside already, so this target is never needed.
rootshell: $(distro)_base.stamp
	$(docker) run --network=host --user 0:0 -v $(shell readlink -f ..):/go/katzenpost --rm -it katzenpost-$(distro)_base $(sh)

test: wait
	cd ../client    && make $(make_args) testargs=$(testargs) dockerdockertest
	cd ../catshadow && make $(make_args) testargs=$(testargs) dockerdockertest
	cd ../memspool  && make $(make_args) testargs=$(testargs) dockerdockertest

check-go-version:
	podman run --rm katzenpost-alpine_base go version
