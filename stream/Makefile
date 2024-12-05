warped?=true
uid=$(shell [ "$$SUDO_UID" != "" ] && echo "$$SUDO_UID" || id -u)
gid=$(shell [ "$$SUDO_GID" != "" ] && echo "$$SUDO_GID" || id -g)
docker_user?=$(shell if echo ${docker}|grep -q podman; then echo 0:0; else echo ${uid}:${gid}; fi)
docker=$(shell if which podman|grep -q .; then echo podman; else echo docker; fi)
distro=alpine
image=katzenpost-$(distro)_base
# mount the package cache from ../docker/cache/go into /go
cache_dir=$(shell readlink -f ../docker)/cache
go_package_cache_arg := -v $(cache_dir)/go:/go/ -e GOCACHE=/go/cache
docker_args=--init -it --user ${docker_user} -v $(shell readlink -f ..):/go/katzenpost $(go_package_cache_arg) --network=host --rm -e GORACE=history_size=7  -w /go/katzenpost/stream

dockerdockertest:
	cd ../docker && make $(distro)_base.stamp
	$(docker) run ${docker_args} $(image) \
		go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -failfast
