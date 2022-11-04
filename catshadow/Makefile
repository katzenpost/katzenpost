warped?=false
ldflags="-X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/minclient/pki.WarpedEpoch=${warped}"
uid=$(shell [ "$$SUDO_UID" != "" ] && echo "$$SUDO_UID" || id -u)
gid=$(shell [ "$$SUDO_GID" != "" ] && echo "$$SUDO_GID" || id -g)
docker_user=${uid}:${gid}
docker_args=--user ${docker_user} -v $(shell readlink -f ..):/go/katzenpost -e GOCACHE=/tmp/gocache --network=host --ulimit memlock=1048576 --rm -it --volume /usr/local/include/sphincsplus:/usr/local/include/sphincsplus

dockerdockertest:
	docker run ${docker_args} katzenpost/deps \
		bash -c 'cd /go/katzenpost/catshadow/; GORACE=history_size=7 go test -ldflags ${ldflags} -tags=docker_test -race -v -timeout 0 -failfast -run Docker'
