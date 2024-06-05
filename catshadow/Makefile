warped?=true
ldflags="-X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped}"
uid=$(shell [ "$$SUDO_UID" != "" ] && echo "$$SUDO_UID" || id -u)
gid=$(shell [ "$$SUDO_GID" != "" ] && echo "$$SUDO_GID" || id -g)
docker_user?=$(shell if echo ${docker}|grep -q podman; then echo 0:0; else echo ${uid}:${gid}; fi)
docker=$(shell if which podman|grep -q .; then echo podman; else echo docker; fi)
distro=alpine
image=katzenpost-$(distro)_base
cache_dir=$(shell readlink -f ../docker)/cache
docker_args=--user ${docker_user} -v $(shell readlink -f ..):/go/katzenpost --network=host --rm -v $(cache_dir)/go:/go/ -v $(cache_dir)/root_cache:/root/.cache

dockerdockertest:
	$(docker) run ${docker_args} $(image) \
		sh -c 'cd /go/katzenpost/catshadow/; GORACE=history_size=7 go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 15m -failfast -run Docker'
