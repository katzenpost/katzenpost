warped?=false
ldflags="-X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/minclient/pki.WarpedEpoch=${warped}"
uid=$(shell [ "$$SUDO_UID" != "" ] && echo "$$SUDO_UID" || id -u)
gid=$(shell [ "$$SUDO_GID" != "" ] && echo "$$SUDO_GID" || id -g)
docker_user=${uid}:${gid}
docker_args=--user ${docker_user} -v $(shell readlink -f ..):/go/katzenpost -e GOCACHE=/tmp/gocache

run-nonvoting-testnet: server nonvoting_authority
	./fix_perms.sh; cd nonvoting_mixnet; DOCKER_USER=${docker_user} docker-compose up -d; docker-compose top

run-voting-testnet: server voting_authority
	./fix_perms.sh; cd voting_mixnet; DOCKER_USER=${docker_user} docker-compose up -d; docker-compose top

stop-voting-testnet:
	cd voting_mixnet; docker-compose down

stop-nonvoting-testnet:
	cd nonvoting_mixnet; docker-compose down

debian_base:
	if ! docker images|grep katzenpost/debian_base; then \
		docker run --name katzenpost_debian_base -it golang:buster bash -c 'apt update && apt upgrade -y' \
		&& docker commit katzenpost_debian_base katzenpost/debian_base \
		&& docker rm katzenpost_debian_base; \
        fi

deps: debian_base
	if ! docker images|grep katzenpost/deps; then \
		docker run ${docker_args} --name katzenpost_deps -it katzenpost/debian_base \
			bash -c 'cd /go/katzenpost; go mod download' \
		&& docker commit katzenpost_deps katzenpost/deps \
		&& docker rm katzenpost_deps; \
        fi

go-mod-tidy: deps
	docker run ${docker_args} --name katzenpost_deps -it katzenpost/deps \
			bash -c 'cd /go/katzenpost; go mod tidy; go mod download' \
		&& docker commit katzenpost_deps katzenpost/deps \
		&& docker rm katzenpost_deps

go-mod-upgrade: deps
	docker run ${docker_args} --name katzenpost_deps -it katzenpost/deps \
			bash -c 'cd /go/katzenpost; go get -d -u ./... && go mod tidy' \
		&& docker commit katzenpost_deps katzenpost/deps \
		&& docker rm katzenpost_deps

server: deps
	if ! docker images|grep katzenpost/server; then \
		docker run ${docker_args} --name katzenpost_server -it katzenpost/deps \
			bash -c 'cd /go/katzenpost/server && make warped=${warped} testnet-build testnet-install' \
		&& docker commit katzenpost_server katzenpost/server \
		&& docker rm katzenpost_server; \
        fi

voting_authority: deps
	if ! docker images|grep katzenpost/voting_authority; then \
		docker run ${docker_args} --name katzenpost_voting_authority -it katzenpost/deps \
			bash -c 'cd /go/katzenpost/authority/cmd/voting && go install -ldflags ${ldflags}' \
		&& docker commit katzenpost_voting_authority katzenpost/voting_authority \
		&& docker rm katzenpost_voting_authority; \
        fi

nonvoting_authority: deps
	if ! docker images|grep katzenpost/nonvoting_authority; then \
		docker run ${docker_args} --name katzenpost_nonvoting_authority -it katzenpost/deps \
			bash -c 'cd /go/katzenpost/authority/cmd/nonvoting && go install -ldflags ${ldflags}' \
		&& docker commit katzenpost_nonvoting_authority katzenpost/nonvoting_authority \
		&& docker rm katzenpost_nonvoting_authority; \
        fi

clean-local-images:
	cd nonvoting_mixnet; docker-compose rm -sf
	cd voting_mixnet; docker-compose rm -sf
	docker rm  katzenpost_server katzenpost_voting_authority katzenpost_nonvoting_authority || true
	docker rmi katzenpost/server katzenpost/voting_authority katzenpost/nonvoting_authority || true

clean-images: clean-local-images
	docker rm  katzenpost_debian_base katzenpost_deps || true
	docker rmi katzenpost/debian_base katzenpost/deps || true

clean-data-dryrun:
	git clean -n nonvoting_mixnet voting_mixnet

clean-data:
	git clean -f nonvoting_mixnet voting_mixnet

clean-local: clean-local-images clean-data

clean: clean-images clean-data

shell: deps
	docker run ${docker_args} --rm -it katzenpost/deps bash

rootshell: deps
	docker run --user 0:0 -v $(shell readlink -f ..):/go/katzenpost --rm -it katzenpost/deps bash

