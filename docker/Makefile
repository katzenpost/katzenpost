warped?=true
mixes=6
auths=6
providers=2
CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f"
ldflags="-buildid= -X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/minclient/pki.WarpedEpoch=${warped}"
uid?=$(shell [ "$$SUDO_UID" != "" ] && echo "$$SUDO_UID" || id -u)
gid?=$(shell [ "$$SUDO_GID" != "" ] && echo "$$SUDO_GID" || id -g)
docker_user=${uid}:${gid}
docker_args=--user ${docker_user} --volume $(shell readlink -f ..):/go/katzenpost --workdir /go/katzenpost -e CGO_CFLAGS_ALLOW=${CGO_CFLAGS_ALLOW}

generate-voting-mixnet-config: server voting_authority
	docker run -e --network=host ${docker_args} --rm katzenpost/deps bash -c 'cd genconfig && go build && cd ../docker && mkdir -p voting_mixnet && ../genconfig/genconfig -nv ${auths} -n ${mixes} -p ${providers} -v -o ./voting_mixnet -b /conf'

#run-nonvoting-testnet: server nonvoting_authority
#	cd nonvoting_mixnet; DOCKER_USER=${docker_user} docker-compose up

run-voting-testnet: generate-voting-mixnet-config
	cd voting_mixnet; DOCKER_USER=${docker_user} docker-compose up

#start-nonvoting-testnet: server nonvoting_authority fix-perms
#	cd nonvoting_mixnet; DOCKER_USER=${docker_user} docker-compose up -d; docker-compose top

start-voting-testnet: server voting_authority generate-voting-mixnet-config
	cd voting_mixnet; DOCKER_USER=${docker_user} docker-compose up -d; docker-compose top

stop-voting-testnet:
	cd voting_mixnet; docker-compose down

#stop-nonvoting-testnet:
#	cd nonvoting_mixnet; docker-compose down

fix-perms:
	./fix_perms.sh

debian_base:
	if ! docker images|grep katzenpost/debian_base; then \
		docker run --name katzenpost_debian_base golang:bullseye bash -c 'adduser katzenpost --gecos "" --disabled-password --uid ${uid} && apt update && apt upgrade -y' \
		&& docker commit katzenpost_debian_base katzenpost/debian_base \
		&& docker rm katzenpost_debian_base; \
        fi

deps: debian_base
	if ! docker images|grep katzenpost/deps; then \
		docker run ${docker_args} --name katzenpost_deps katzenpost/debian_base \
			bash -c 'go mod download && cd sphincsplus/ref && go install' \
		&& docker commit katzenpost_deps katzenpost/deps \
		&& docker rm katzenpost_deps; \
        fi

go-mod-tidy: deps
	docker run ${docker_args} --name katzenpost_deps katzenpost/deps \
			bash -c "go mod tidy" \
		&& docker commit katzenpost_deps katzenpost/deps \
		&& docker rm katzenpost_deps

go-mod-upgrade: deps
	docker run ${docker_args} --name katzenpost_deps katzenpost/deps \
			bash -c 'go get -d -u ./... && go mod tidy' \
		&& docker commit katzenpost_deps katzenpost/deps \
		&& docker rm katzenpost_deps

server: deps
	if ! docker images|grep katzenpost/server; then \
		docker run ${docker_args} --name katzenpost_server katzenpost/deps \
			bash -c 'cd server && warped=${warped} make testnet-build testnet-install' \
		&& docker commit katzenpost_server katzenpost/server \
		&& docker rm katzenpost_server; \
        fi

voting_authority: deps
	if ! docker images|grep katzenpost/voting_authority; then \
		docker run ${docker_args} --name katzenpost_voting_authority katzenpost/deps \
			bash -c 'cd authority/cmd/voting && go mod verify && go install -trimpath -ldflags ${ldflags}' \
		&& docker commit katzenpost_voting_authority katzenpost/voting_authority \
		&& docker rm katzenpost_voting_authority; \
        fi

nonvoting_authority: deps
	if ! docker images|grep katzenpost/nonvoting_authority; then \
		docker run ${docker_args} --name katzenpost_nonvoting_authority katzenpost/deps \
			bash -c 'cd authority/cmd/nonvoting && go mod verify && go install -trimpath -ldflags ${ldflags}' \
		&& docker commit katzenpost_nonvoting_authority katzenpost/nonvoting_authority \
		&& docker rm katzenpost_nonvoting_authority; \
        fi

clean-local-images:
	cd nonvoting_mixnet; docker-compose rm -sf
	cd voting_mixnet; docker-compose rm -sf
	docker rm  katzenpost_server katzenpost_voting_authority katzenpost_nonvoting_authority katzenpost_ping || true
	docker rmi katzenpost/server katzenpost/voting_authority katzenpost/nonvoting_authority katzenpost/ping || true

clean-images: clean-local-images
	docker rm  katzenpost_debian_base katzenpost_deps || true
	docker rmi katzenpost/debian_base katzenpost/deps || true

clean-data-dryrun:
	git clean -n -x nonvoting_mixnet voting_mixnet

clean-data:
	git clean -f -x nonvoting_mixnet voting_mixnet

clean-local: clean-local-images clean-data

clean: clean-images clean-data

ping: deps
	if ! docker images|grep katzenpost/ping; then \
		docker run ${docker_args} --name katzenpost_ping katzenpost/deps \
			bash -c 'cd ping && go mod verify && go install -ldflags ${ldflags}' \
		&& docker commit katzenpost_ping katzenpost/ping \
		&& docker rm katzenpost_ping; \
        fi

ping-rebuild: deps
		docker run ${docker_args} --name katzenpost_ping katzenpost/deps \
			bash -c 'cd ping && go mod verify && go install -ldflags ${ldflags}' \
		&& docker commit katzenpost_ping katzenpost/ping \
		&& docker rm katzenpost_ping; \

run-ping: ping
	docker run --network=host ${docker_args} --rm katzenpost/ping \
        /go/bin/ping -c /go/katzenpost/docker/voting_mixnet/conf/client/client.toml -s echo -printDiff -n 1

shell: deps
	docker run -e --network=host ${docker_args} --rm -it katzenpost/deps bash

rootshell: deps
	docker run --network=host --user 0:0 -v $(shell readlink -f ..):/go/katzenpost --rm -it katzenpost/deps bash

