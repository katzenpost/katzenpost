.PHONY: clean clean-local clean-data clean-data-dryrun clean-image-% clean-container-% clean-images clean-local-images test rootshell shell run-ping go-mod-tidy go-mod-upgrade help start-voting-testnet run-voting-testnet stop-voting-testnet

help:
	@echo "Interesting make targets:"
	@echo " run-voting-testnet    - run the testnet until ctrl-C"
	@echo " start-voting-testnet  - run the testnet in the background"
	@echo " stop-voting-testnet   - stop it"
	@echo " run-ping              - send a ping over the testnet"
	@echo " clean-data            - delete data"
	@echo " clean-local           - delete offline-rebuildable images"
	@echo " clean                 - delete everything (requires internet to rebuild)"
	@echo

warped?=true
mixes=6
auths=6
providers=2
distro=alpine
net_name=voting_mixnet
docker_compose_yml=$(net_name)/docker-compose.yml
sh=$(shell if echo ${distro}|grep -q alpine; then echo sh; else echo bash; fi)

# note: currently docker still defaults to docker, until we test podman a
# little more. to use podman (still with docker compose, but now rootless!) set
# docker=podman

# maybe relevant issue: https://github.com/containers/podman/issues/9447 (or
# probably not anymore, now that we're in the host network namespace)

docker=$(shell if which podman|grep -q .; then echo podman; else echo docker; fi)

ldflags="-buildid= -X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/minclient/pki.WarpedEpoch=${warped}"

uid?=$(shell [ "$$SUDO_UID" != "" ] && echo "$$SUDO_UID" || id -u)
gid?=$(shell [ "$$SUDO_GID" != "" ] && echo "$$SUDO_GID" || id -g)
CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f"
DISTROS=alpine debian
IMAGES=server voting_authority ping

docker_user?=$(shell if echo ${docker}|grep -q podman; then echo 0:0; else echo ${uid}:${gid}; fi)
replace_name=$(shell if echo ${docker}|grep -q podman; then echo " --replace --name"; else echo " --name"; fi)
i_if_podman=$(shell if echo ${docker}|grep -q podman; then echo " -i"; else echo; fi)
docker_args=--user ${docker_user} --volume $(shell readlink -f ..):/go/katzenpost --workdir /go/katzenpost -e CGO_CFLAGS_ALLOW=${CGO_CFLAGS_ALLOW}
docker_compose?= $(shell if echo ${docker}|grep -q podman; then echo DOCKER_HOST="unix:$$XDG_RUNTIME_DIR/podman/podman.sock" docker-compose; else echo docker-compose; fi)

make_args=--no-print-directory net_name=$(net_name) docker=$(docker) warped=$(warped) docker_user=$(docker_user)

$(docker_compose_yml): ../genconfig/main.go $(distro)_go_mod.stamp
	$(docker) run -e --network=host ${docker_args} --rm katzenpost-$(distro)_go_mod $(sh) -c 'cd genconfig && go build && cd ../docker && mkdir -p $(net_name) && ../genconfig/genconfig -nv ${auths} -n ${mixes} -p ${providers} -v -o ./$(net_name) -b /conf'

run-voting-testnet: server voting_authority $(docker_compose_yml)
	cd $(net_name); DOCKER_USER=${docker_user} $(docker_compose) up --remove-orphans

start-voting-testnet: server voting_authority $(docker_compose_yml)
	cd $(net_name); DOCKER_USER=${docker_user} $(docker_compose) up --remove-orphans -d; $(docker_compose) top

stop-voting-testnet:
	cd $(net_name); $(docker_compose) down

#run-nonvoting-testnet: server nonvoting_authority
#	cd nonvoting_mixnet; DOCKER_USER=${docker_user} docker-compose up

#start-nonvoting-testnet: server nonvoting_authority fix-perms
#	cd nonvoting_mixnet; DOCKER_USER=${docker_user} docker-compose up -d; docker-compose top

#stop-nonvoting-testnet:
#	cd nonvoting_mixnet; docker-compose down

debian_base.stamp:
	$(docker) run $(replace_name) katzenpost_debian_base docker.io/golang:bullseye $(sh) -c 'adduser katzenpost --gecos "" --disabled-password --uid ${uid} && apt update && apt upgrade -y'
	$(docker) commit katzenpost_debian_base katzenpost-debian_base
	$(docker) rm katzenpost_debian_base
	touch $@
	

alpine_base.stamp:
	$(docker) run $(replace_name) katzenpost_alpine_base docker.io/golang:alpine sh -c 'adduser katzenpost --gecos "" --disabled-password  && apk update && apk upgrade && apk add gcc musl-dev make' \
	&& $(docker) commit katzenpost_alpine_base katzenpost-alpine_base \
	&& $(docker) rm katzenpost_alpine_base
	touch $@

$(distro)_go_mod.stamp: $(distro)_base.stamp
	$(docker) run ${docker_args} $(replace_name) \
		katzenpost_$(distro)_go_mod katzenpost-$(distro)_base \
		sh -c 'go mod download && cd sphincsplus/ref && go install'
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

server: $(distro)_go_mod.stamp
	if ! $(docker) images|grep katzenpost-server; then \
		$(docker) run ${docker_args} $(replace_name) katzenpost_server katzenpost-$(distro)_go_mod \
			$(sh) -c 'cd server && warped=${warped} make testnet-build testnet-install' \
		&& $(docker) commit katzenpost_server katzenpost-server \
		&& $(docker) rm katzenpost_server; \
        fi

voting_authority: $(distro)_go_mod.stamp
	if ! $(docker) images|grep katzenpost-voting_authority; then \
		$(docker) run ${docker_args} $(replace_name) katzenpost_voting_authority katzenpost-$(distro)_go_mod \
			$(sh) -c 'cd authority/cmd/voting && go mod verify && go install -trimpath -ldflags ${ldflags}' \
		&& $(docker) commit katzenpost_voting_authority katzenpost-voting_authority \
		&& $(docker) rm katzenpost_voting_authority; \
        fi

clean-local-images:
	-cd $(net_name) && $(docker_compose) rm -sf
	for image in $(IMAGES); do \
		make $(make_args) clean-container-$$image; \
		make $(make_args) clean-image-$$image; \
	done

#	@-for distro in $(DISTROS); do \
#		for image in $(IMAGES); do \
#			make $(make_args) clean-container-$$distro_$$image; \
#			make $(make_args) clean-image-$$distro-$$image; \
#		done; \
#	done

clean-images: clean-local-images
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

clean-data-dryrun:
	git clean -n -x nonvoting_mixnet $(net_name)

clean-data:
	git clean -f -x nonvoting_mixnet $(net_name)
	git status .

clean-local: clean-local-images clean-data

clean: clean-images clean-data
	-$(docker) ps -a|grep katzenpost|cat
	-$(docker) images|grep katzenpost|cat

ping.stamp: $(distro)_go_mod.stamp
	if ! $(docker) images|grep katzenpost-ping; then \
		$(docker) run ${docker_args} $(replace_name) katzenpost_ping katzenpost-$(distro)_go_mod \
			$(sh) -c 'cd ping && go mod verify && go install -ldflags ${ldflags}' \
		&& $(docker) commit katzenpost_ping katzenpost-ping \
		&& $(docker) rm katzenpost_ping; \
        fi
	touch $@

run-ping: ping.stamp start-voting-testnet
	$(docker) run --network=host ${docker_args} --rm katzenpost-ping \
        /go/bin/ping -c /go/katzenpost/docker/$(net_name)/client/client.toml -s echo -printDiff -n 1

shell: $(distro)_go_mod.stamp
	$(docker) run -e --network=host ${docker_args} --rm -it katzenpost-$(distro)_go_mod $(sh)

rootshell: $(distro)_go_mod
	$(docker) run --network=host --user 0:0 -v $(shell readlink -f ..):/go/katzenpost --rm -it katzenpost-$(distro)_go_mod $(sh)

test: start-voting-testnet
	cd ../client    && make $(make_args) testargs=$(testargs) dockerdockertest
	cd ../catshadow && make $(make_args) testargs=$(testargs) dockerdockertest
	cd ../memspool  && make $(make_args) testargs=$(testargs) dockerdockertest

