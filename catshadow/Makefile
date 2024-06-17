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

test_version=v30

dockerdockertest:
	$(docker) run ${docker_args} $(image) \
		sh -c 'cd /go/katzenpost/catshadow/; GORACE=history_size=7 go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 0 -failfast -run Docker'

upgrade_test_use_saved:
	cd ../docker && make wait && cd ../catshadow && \
	cp -v testdata/$(test_version)/*state testdata/ && \
		echo STOP_KAETZCHEN spool|socat - unix:../docker/voting_mixnet/servicenode1/management_sock && \
		cp -v testdata/$(test_version)/memspool.storage ../docker/voting_mixnet/servicenode1/ && \
		echo START_KAETZCHEN spool|socat - unix:../docker/voting_mixnet/servicenode1/management_sock && \
	$(docker) run ${docker_args} $(image) \
		sh -c 'cd /go/katzenpost/catshadow/; GORACE=history_size=7 go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 0 -failfast -run UpgradeResume'
#	$(docker) run ${docker_args} $(image) \
#		sh -c 'cd /go/katzenpost/catshadow/; GORACE=history_size=7 go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 0 -failfast -run UpgradeResume_1'

upgrade_test_recreate:
	cd ../docker && make wait
	echo STOP_KAETZCHEN spool|socat - unix:../docker/voting_mixnet/servicenode1/management_sock
	rm -fv ../docker/voting_mixnet/servicenode1/memspool.storage
	echo START_KAETZCHEN spool|socat - unix:../docker/voting_mixnet/servicenode1/management_sock
	$(docker) run ${docker_args} $(image) \
		sh -c 'cd /go/katzenpost/catshadow/; GORACE=history_size=7 go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 0 -failfast -run UpgradeCreate'
	echo STOP_KAETZCHEN spool|socat - unix:../docker/voting_mixnet/servicenode1/management_sock
	mkdir -p testdata/$(test_version)/
	cp -v ../docker/voting_mixnet/servicenode1/memspool.storage \
			testdata/*state testdata/$(test_version)/
	echo START_KAETZCHEN spool|socat - unix:../docker/voting_mixnet/servicenode1/management_sock

clean:
	rm -fv testdata/*state testdata/*.storage
