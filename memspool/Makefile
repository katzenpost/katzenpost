warped?=true
ldflags="-X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped}"
uid=$(shell [ "$$SUDO_UID" != "" ] && echo "$$SUDO_UID" || id -u)
gid=$(shell [ "$$SUDO_GID" != "" ] && echo "$$SUDO_GID" || id -g)
docker_user?=$(shell if echo ${docker}|grep -q podman; then echo 0:0; else echo ${uid}:${gid}; fi)
docker=$(shell if which podman|grep -q .; then echo podman; else echo docker; fi)
distro=alpine
image=katzenpost-$(distro)_base
cache_dir=$(shell readlink -f ../docker)/cache
docker_args=--init -it --user ${docker_user} -v $(shell readlink -f ..):/go/katzenpost --network=host --rm -v $(cache_dir)/go:/go/ -e GOCACHE=/go/cache -e GORACE=history_size=7 -w /go/katzenpost/memspool/client

dockerdockertest:
	cd ../docker && make $(distro)_base.stamp
	$(docker) run ${docker_args} $(image) \
		go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 30m -failfast -run Docker
