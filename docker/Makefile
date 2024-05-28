.PHONY: clean clean-local clean-local-dryrun clean-image-% clean-container-% clean-images test rootshell shell run-ping go-mod-tidy go-mod-upgrade help start run stop

help:
	@echo "These make targets allow you to control the test network:"
	@echo " run                - run the testnet in the foreground, until ctrl-C"
	@echo " start              - start the testnet in the background"
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
mixes=3
auths=3
gateways=1
serviceNodes=1

pings=1
ping_concurrency=$(pings)

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
SHELL=/bin/bash

# log_level can be DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL
log_level=DEBUG

docker=$(shell if which podman|grep -q .; then echo podman; else echo docker; fi)

ldflags="-buildid= -X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped}"

uid?=$(shell [ "$$SUDO_UID" != "" ] && echo "$$SUDO_UID" || id -u)
gid?=$(shell [ "$$SUDO_GID" != "" ] && echo "$$SUDO_GID" || id -g)

docker_user?=$(shell if echo ${docker}|grep -q podman; then echo 0:0; else echo ${uid}:${gid}; fi)
docker_args=--user ${docker_user} --volume $(shell readlink -f ..):/go/katzenpost --workdir /go/katzenpost

replace_name=$(shell if echo ${docker}|grep -q podman; then echo " --replace --name"; else echo " --name"; fi)
i_if_podman=$(shell if echo ${docker}|grep -q podman; then echo " -i"; else echo; fi)
mount_net_name=-v `pwd`/$(net_name):/$(net_name)

docker_compose?= $(shell if echo ${docker}|grep -q podman; then echo DOCKER_HOST="unix://$$XDG_RUNTIME_DIR/podman/podman.sock" docker-compose; else echo docker-compose; fi)

make_args=--no-print-directory net_name=$(net_name) docker=$(docker) distro=$(distro) warped=$(warped) docker_user=$(docker_user)

$(docker_compose_yml): ../genconfig/main.go $(distro)_go_mod.stamp
	mkdir -p $(net_name)
	$(docker) run ${docker_args} --rm katzenpost-$(distro)_go_mod \
		$(sh) -c 'cd genconfig && go build && cd ../docker \
		&& ../genconfig/genconfig -wirekem $(wirekem) -a ${bind_addr} -nv ${auths} -n ${mixes} -gateways ${gateways} \
		-serviceNodes ${serviceNodes} \
		-sr ${sr} -mu ${mu} -muMax ${muMax} -lP ${lP} -lPMax ${lPMax} -lL ${lL} \
		-lLMax ${lLMax} -lD ${lD} -lDMax ${lDMax} -lM ${lM} -lMMax ${lMMax} \
		-S .$(distro) -v -o ./$(net_name) -b /$(net_name) -P $(base_port) \
		-nike "$(nike)" -kem "$(kem)" -d katzenpost-$(distro)_go_mod \
		-UserForwardPayloadLength $(UserForwardPayloadLength) -log_level $(log_level)'

$(net_name)/running.stamp:
	make $(make_args) start

run: $(docker_compose_yml) $(net_name)/server.$(distro) $(net_name)/voting.$(distro)
	cd $(net_name) && touch running.stamp \
	&& DOCKER_USER=${docker_user} $(docker_compose) up --remove-orphans
	cd $(net_name) && rm -v running.stamp

start: $(docker_compose_yml) $(net_name)/server.$(distro) $(net_name)/voting.$(distro)
	cd $(net_name); DOCKER_USER=${docker_user} $(docker_compose) up --remove-orphans -d; $(docker_compose) top
	touch $(net_name)/running.stamp

stop:
	cd $(net_name) && $(docker_compose) down --remove-orphans; rm -fv running.stamp

watch:
	tail -F $(net_name)/*/*.log

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

wait: $(net_name)/running.stamp
	$(docker) run --network=host ${docker_args} $(mount_net_name) --rm  katzenpost-$(distro)_go_mod \
	/$(net_name)/fetch.$(distro) -f /$(net_name)/client/client.toml

debian_base.stamp:
	$(docker) run $(replace_name) katzenpost_debian_base docker.io/golang:bullseye $(sh) -c 'adduser katzenpost --gecos "" --disabled-password --uid ${uid} && apt update && apt upgrade -y'
	$(docker) commit katzenpost_debian_base katzenpost-debian_base
	$(docker) rm katzenpost_debian_base
	touch $@

alpine_base.stamp:
	$(docker) run $(replace_name) katzenpost_alpine_base docker.io/golang:1.21-alpine sh -c 'adduser katzenpost --gecos "" --disabled-password  && apk update && apk upgrade && apk add gcc musl-dev make' \
	&& $(docker) commit katzenpost_alpine_base katzenpost-alpine_base \
	&& $(docker) rm katzenpost_alpine_base
	touch $@

$(distro)_go_mod.stamp: $(distro)_base.stamp
	$(docker) run ${docker_args} $(replace_name) \
		katzenpost_$(distro)_go_mod katzenpost-$(distro)_base \
		sh -c 'go mod download'
	$(docker) commit katzenpost_$(distro)_go_mod katzenpost-$(distro)_go_mod
	$(docker) rm katzenpost_$(distro)_go_mod
	touch $@

go-mod-tidy: $(distro)_go_mod.stamp
	$(docker) run ${docker_args} $(replace_name) katzenpost_$(distro)_go_mod katzenpost-$(distro)_go_mod \
			$(sh) -c "go mod tidy" \
		&& $(docker) commit katzenpost_$(distro)_go_mod katzenpost-$(distro)_go_mod \
		&& $(docker) rm katzenpost_$(distro)_go_mod

go-mod-upgrade: $(distro)_go_mod.stamp
	$(docker) run ${docker_args} $(replace_name) katzenpost_$(distro)_go_mod katzenpost-$(distro)_go_mod \
			$(sh) -c 'go get -d -u ./... && go mod tidy' \
		&& $(docker) commit katzenpost_$(distro)_go_mod katzenpost-$(distro)_go_mod \
		&& $(docker) rm katzenpost_$(distro)_go_mod

$(net_name)/server.$(distro): $(distro)_go_mod.stamp $(docker_compose_yml)
		$(docker) run ${docker_args} $(mount_net_name) --rm katzenpost-$(distro)_go_mod \
			$(sh) -c 'cd server && make $(make_args) testnet-build testnet-install'

$(net_name)/voting.$(distro): $(distro)_go_mod.stamp $(docker_compose_yml)
		$(docker) run ${docker_args} $(mount_net_name) --rm katzenpost-$(distro)_go_mod \
			$(sh) -c 'cd authority && make $(make_args) cmd/voting/voting cmd/fetch/fetch && \
			mv cmd/voting/voting /$(net_name)/voting.$(distro) && \
			mv cmd/fetch/fetch /$(net_name)/fetch.$(distro)'

$(net_name)/ping.$(distro): $(distro)_go_mod.stamp
		$(docker) run ${docker_args} $(mount_net_name) --rm katzenpost-$(distro)_go_mod \
			$(sh) -c 'cd ping && go mod verify && go build -ldflags ${ldflags} && \
			mv ping /$(net_name)/ping.$(distro)'

clean-images: stop
	@-for distro in $(DISTROS); do \
		for image in base go_mod; do \
			make $(make_args) distro=$$distro clean-container-$${distro}_$$image; \
			make $(make_args) distro=$$distro clean-image-$${distro}_$$image; \
		done; \
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
	-$(docker) ps -a|grep katzenpost|cat
	-$(docker) images|grep katzenpost|cat

run-ping: $(net_name)/ping.$(distro) $(net_name)/running.stamp
	$(docker) run --network=host ${docker_args} $(mount_net_name) --rm  katzenpost-$(distro)_go_mod \
        /$(net_name)/ping.$(distro) -c /go/katzenpost/docker/$(net_name)/client/client.toml -s echo -printDiff -n $(pings) -C $(ping_concurrency)

shell: $(distro)_go_mod.stamp
	$(docker) run --network=host ${docker_args} $(mount_net_name) -w /go/katzenpost/docker/$(net_name) --rm -it katzenpost-$(distro)_go_mod $(sh)

# this is for running with docker, where we are root outside and (except for
# here) non-root inside. When using podman, we are rootless outside and uid 0
# inside already, so this target is never needed.
rootshell: $(distro)_go_mod
	$(docker) run --network=host --user 0:0 -v $(shell readlink -f ..):/go/katzenpost --rm -it katzenpost-$(distro)_go_mod $(sh)

test: wait
	cd ../client    && make $(make_args) testargs=$(testargs) dockerdockertest
	cd ../catshadow && make $(make_args) testargs=$(testargs) dockerdockertest
	cd ../memspool  && make $(make_args) testargs=$(testargs) dockerdockertest

check-go-version:
	podman run --rm katzenpost-alpine_base go version
