
warped?=true
mixes=6
auths=6
providers=2
CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f"

net_name=voting_mixnet
docker_compose_yml=$(net_name)/docker-compose.yml

ldflags="-buildid= -X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/minclient/pki.WarpedEpoch=${warped}"
uid?=$(shell [ "$$SUDO_UID" != "" ] && echo "$$SUDO_UID" || id -u)
gid?=$(shell [ "$$SUDO_GID" != "" ] && echo "$$SUDO_GID" || id -g)


# note: currently docker still defaults to docker, until we test podman a
# little more. to use podman (still with docker compose, but now rootless!) set
# docker=podman

# maybe relevant issue: https://github.com/containers/podman/issues/9447 (or
# probably not anymore, now that we're in the host network namespace)

# work with podman there. In the current state now, you can say make
# docker=podman and run the non-docker-compose make targets here.

# docker?= $(shell if which podman|grep -q . && conmon --version|grep -q '2\.1\.3'; then echo podman; else echo docker; fi)
docker=docker
docker_user?=$(shell if echo ${docker}|grep -q podman; then echo 0:0; else echo ${uid}:${gid}; fi)
docker_args=--user ${docker_user} --volume $(shell readlink -f ..):/go/katzenpost --workdir /go/katzenpost -e CGO_CFLAGS_ALLOW=${CGO_CFLAGS_ALLOW}
docker_compose?= $(shell if echo ${docker}|grep -q podman; then echo DOCKER_HOST="unix:$$XDG_RUNTIME_DIR/podman/podman.sock" docker-compose; else echo docker-compose; fi)

$(docker_compose_yml): ../genconfig/main.go
	$(docker) run -e --network=host ${docker_args} --rm katzenpost/deps bash -c 'cd genconfig && go build && cd ../docker && mkdir -p $(net_name) && ../genconfig/genconfig -nv ${auths} -n ${mixes} -p ${providers} -v -o ./$(net_name) -b /conf'

run-voting-testnet: server voting_authority $(docker_compose_yml)
	cd $(net_name); DOCKER_USER=${docker_user} $(docker_compose) up

start-voting-testnet: server voting_authority $(docker_compose_yml)
	cd $(net_name); DOCKER_USER=${docker_user} $(docker_compose) up -d; $(docker_compose) top

stop-voting-testnet:
	cd $(net_name); $(docker_compose) down

#run-nonvoting-testnet: server nonvoting_authority
#	cd nonvoting_mixnet; DOCKER_USER=${docker_user} docker-compose up

#start-nonvoting-testnet: server nonvoting_authority fix-perms
#	cd nonvoting_mixnet; DOCKER_USER=${docker_user} docker-compose up -d; docker-compose top

#stop-nonvoting-testnet:
#	cd nonvoting_mixnet; docker-compose down

fix-perms:
	./fix_perms.sh

debian_base:
	if ! $(docker) images|grep katzenpost/debian_base; then \
		$(docker) run --name katzenpost_debian_base golang:bullseye bash -c 'adduser katzenpost --gecos "" --disabled-password --uid ${uid} && apt update && apt upgrade -y' \
		&& $(docker) commit katzenpost_debian_base katzenpost/debian_base \
		&& $(docker) rm katzenpost_debian_base; \
        fi

deps: debian_base
	if ! $(docker) images|grep katzenpost/deps; then \
		$(docker) run ${docker_args} --name katzenpost_deps katzenpost/debian_base \
			bash -c 'go mod download && cd sphincsplus/ref && go install' \
		&& $(docker) commit katzenpost_deps katzenpost/deps \
		&& $(docker) rm katzenpost_deps; \
        fi

go-mod-tidy: deps
	$(docker) run ${docker_args} --name katzenpost_deps katzenpost/deps \
			bash -c "go mod tidy" \
		&& $(docker) commit katzenpost_deps katzenpost/deps \
		&& $(docker) rm katzenpost_deps

go-mod-upgrade: deps
	$(docker) run ${docker_args} --name katzenpost_deps katzenpost/deps \
			bash -c 'go get -d -u ./... && go mod tidy' \
		&& $(docker) commit katzenpost_deps katzenpost/deps \
		&& $(docker) rm katzenpost_deps

server: deps
	if ! $(docker) images|grep katzenpost/server; then \
		$(docker) run ${docker_args} --name katzenpost_server katzenpost/deps \
			bash -c 'cd server && warped=${warped} make testnet-build testnet-install' \
		&& $(docker) commit katzenpost_server katzenpost/server \
		&& $(docker) rm katzenpost_server; \
        fi

voting_authority: deps
	if ! $(docker) images|grep katzenpost/voting_authority; then \
		$(docker) run ${docker_args} --name katzenpost_voting_authority katzenpost/deps \
			bash -c 'cd authority/cmd/voting && go mod verify && go install -trimpath -ldflags ${ldflags}' \
		&& $(docker) commit katzenpost_voting_authority katzenpost/voting_authority \
		&& $(docker) rm katzenpost_voting_authority; \
        fi

nonvoting_authority: deps
	if ! $(docker) images|grep katzenpost/nonvoting_authority; then \
		$(docker) run ${docker_args} --name katzenpost_nonvoting_authority katzenpost/deps \
			bash -c 'cd authority/cmd/nonvoting && go mod verify && go install -trimpath -ldflags ${ldflags}' \
		&& $(docker) commit katzenpost_nonvoting_authority katzenpost/nonvoting_authority \
		&& $(docker) rm katzenpost_nonvoting_authority; \
        fi

clean-local-images:
	-cd nonvoting_mixnet && $(docker_compose) rm -sf
	-cd $(net_name) && $(docker_compose) rm -sf
	-$(docker) rm  katzenpost_server katzenpost_voting_authority katzenpost_nonvoting_authority katzenpost_ping
	-$(docker) rmi katzenpost/server katzenpost/voting_authority katzenpost/nonvoting_authority katzenpost/ping

clean-images: clean-local-images
	-$(docker) rm  katzenpost_debian_base katzenpost_deps
	-$(docker) rmi katzenpost/debian_base katzenpost/deps

clean-data-dryrun:
	git clean -n -x nonvoting_mixnet $(net_name)

clean-data:
	git clean -f -x nonvoting_mixnet $(net_name)

clean-local: clean-local-images clean-data

clean: clean-images clean-data

ping: deps
	if ! $(docker) images|grep katzenpost/ping; then \
		$(docker) run ${docker_args} --name katzenpost_ping katzenpost/deps \
			bash -c 'cd ping && go mod verify && go install -ldflags ${ldflags}' \
		&& $(docker) commit katzenpost_ping katzenpost/ping \
		&& $(docker) rm katzenpost_ping; \
        fi

ping-rebuild: deps
		$(docker) run ${docker_args} --name katzenpost_ping katzenpost/deps \
			bash -c 'cd ping && go mod verify && go install -ldflags ${ldflags}' \
		&& $(docker) commit katzenpost_ping katzenpost/ping \
		&& $(docker) rm katzenpost_ping; \

run-ping: ping start-voting-testnet
	$(docker) run --network=host ${docker_args} --rm katzenpost/ping \
        /go/bin/ping -c /go/katzenpost/docker/$(net_name)/client/client.toml -s echo -printDiff -n 1

shell: deps
	$(docker) run -e --network=host ${docker_args} --rm -it katzenpost/deps bash

rootshell: deps
	$(docker) run --network=host --user 0:0 -v $(shell readlink -f ..):/go/katzenpost --rm -it katzenpost/deps bash

test: start-voting-testnet
	cd ../client && make docker=$(docker) dockerdockertest
	cd ../catshadow && docker=$(docker) make dockerdockertest
	cd ../memspool && docker=$(docker) make dockerdockertest
