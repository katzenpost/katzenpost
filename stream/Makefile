warped?=true
ldflags="-X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/minclient/pki.WarpedEpoch=${warped}"
uid=$(shell [ "$$SUDO_UID" != "" ] && echo "$$SUDO_UID" || id -u)
gid=$(shell [ "$$SUDO_GID" != "" ] && echo "$$SUDO_GID" || id -g)
docker_user?=$(shell if echo ${docker}|grep -q podman; then echo 0:0; else echo ${uid}:${gid}; fi)
docker=$(shell if which podman|grep -q .; then echo podman; else echo docker; fi)
cache_dir=cache
distro=alpine
image=katzenpost-$(distro)_base
# mount the package cache from ../docker/cache/go into /go
go_package_cache_arg := -v $(shell readlink -f ../docker)/$(cache_dir)/go:/go/ -e GOCACHE=/go/cache
docker_args=--init -it --user ${docker_user} -v $(shell readlink -f ..):/go/katzenpost $(go_package_cache_arg) --network=host --rm -w /go/katzenpost/stream

dockerdockertest:
	$(docker) run -e GORACE=history_size=7 ${docker_args} $(image) \
		go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -failfast
