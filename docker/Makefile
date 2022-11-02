warped?=false
ldflags="-X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/minclient/pki.WarpedEpoch=${warped}"
uid?=$(shell [ "$$SUDO_UID" != "" ] && echo "$$SUDO_UID" || id -u)
gid?=$(shell [ "$$SUDO_GID" != "" ] && echo "$$SUDO_GID" || id -g)
docker_user=${uid}:${gid}
docker_args=--user ${docker_user} --volume $(shell readlink -f ..):/go/katzenpost --volume /usr/local/include/sphincsplus:/usr/local/include/sphincsplus --workdir /go/katzenpost

run-nonvoting-testnet: server nonvoting_authority fix-perms
	cd nonvoting_mixnet; DOCKER_USER=${docker_user} docker-compose up

run-voting-testnet: server voting_authority fix-perms
	cd voting_mixnet; DOCKER_USER=${docker_user} docker-compose up

start-nonvoting-testnet: server nonvoting_authority fix-perms
	cd nonvoting_mixnet; DOCKER_USER=${docker_user} docker-compose up -d; docker-compose top

start-voting-testnet: server voting_authority fix-perms
	cd voting_mixnet; DOCKER_USER=${docker_user} docker-compose up -d; docker-compose top

stop-voting-testnet:
	cd voting_mixnet; docker-compose down

stop-nonvoting-testnet:
	cd nonvoting_mixnet; docker-compose down

fix-perms:
	./fix_perms.sh

debian_base:
	if ! docker images|grep katzenpost/debian_base; then \
		docker run --volume /usr/local/lib/libsphincsplus.so:/libsphincsplus.so --name katzenpost_debian_base -it golang:bullseye bash -c 'adduser katzenpost --gecos "" --disabled-password --uid ${uid} && apt update && apt upgrade -y && cp /libsphincsplus.so /usr/local/lib && ldconfig -v' \
		&& docker commit katzenpost_debian_base katzenpost/debian_base \
		&& docker rm katzenpost_debian_base; \
        fi

deps: debian_base
	if ! docker images|grep katzenpost/deps; then \
		docker run ${docker_args} --name katzenpost_deps -it katzenpost/debian_base \
			go mod download \
		&& docker commit katzenpost_deps katzenpost/deps \
		&& docker rm katzenpost_deps; \
        fi

go-mod-tidy: deps
	docker run ${docker_args} --name katzenpost_deps -it katzenpost/deps \
			go mod tidy \
		&& docker commit katzenpost_deps katzenpost/deps \
		&& docker rm katzenpost_deps

go-mod-upgrade: deps
	docker run ${docker_args} --name katzenpost_deps -it katzenpost/deps \
			bash -c 'go get -d -u ./... && go mod tidy' \
		&& docker commit katzenpost_deps katzenpost/deps \
		&& docker rm katzenpost_deps

server: deps
	if ! docker images|grep katzenpost/server; then \
		docker run ${docker_args} --name katzenpost_server -it katzenpost/deps \
			bash -c 'cd server && make warped=${warped} testnet-build testnet-install' \
		&& docker commit katzenpost_server katzenpost/server \
		&& docker rm katzenpost_server; \
        fi

voting_authority: deps
	if ! docker images|grep katzenpost/voting_authority; then \
		docker run ${docker_args} --name katzenpost_voting_authority -it katzenpost/deps \
			bash -c 'cd authority/cmd/voting && go mod verify && go install -ldflags ${ldflags}' \
		&& docker commit katzenpost_voting_authority katzenpost/voting_authority \
		&& docker rm katzenpost_voting_authority; \
        fi

nonvoting_authority: deps
	if ! docker images|grep katzenpost/nonvoting_authority; then \
		docker run ${docker_args} --name katzenpost_nonvoting_authority -it katzenpost/deps \
			bash -c 'cd authority/cmd/nonvoting && go mod verify && go install -ldflags ${ldflags}' \
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
	git clean -n nonvoting_mixnet voting_mixnet

clean-data:
	git clean -f nonvoting_mixnet voting_mixnet

clean-local: clean-local-images clean-data

clean: clean-images clean-data

ping: deps
	if ! docker images|grep katzenpost/ping; then \
		docker run ${docker_args} --name katzenpost_ping -it katzenpost/deps \
			bash -c 'cd ping && go mod verify && go install -ldflags ${ldflags}' \
		&& docker commit katzenpost_ping katzenpost/ping \
		&& docker rm katzenpost_ping; \
        fi

ping-rebuild: deps
		docker run ${docker_args} --name katzenpost_ping -it katzenpost/deps \
			bash -c 'cd ping && go mod verify && go install -ldflags ${ldflags}' \
		&& docker commit katzenpost_ping katzenpost/ping \
		&& docker rm katzenpost_ping; \

run-ping: ping
	docker run --network=host ${docker_args} --rm -it katzenpost/ping \
        /go/bin/ping -c /go/katzenpost/ping/nonvoting_docker_mixnet.toml -s echo -printDiff -n 1

shell: deps
	docker run --network=host ${docker_args} --rm -it katzenpost/deps bash

rootshell: deps
	docker run --network=host --user 0:0 -v $(shell readlink -f ..):/go/katzenpost --rm -it katzenpost/deps bash

