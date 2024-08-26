warped?=true
ldflags="-X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped}"
uid=$(shell [ "$$SUDO_UID" != "" ] && echo "$$SUDO_UID" || id -u)
gid=$(shell [ "$$SUDO_GID" != "" ] && echo "$$SUDO_GID" || id -g)
docker_user?=$(shell if echo ${docker}|grep -q podman; then echo 0:0; else echo ${uid}:${gid}; fi)
docker=$(shell if which podman|grep -q .; then echo podman; else echo docker; fi)
distro=alpine
image=katzenpost-$(distro)_base
cache_dir=$(shell readlink -f ../docker)/cache
docker_args=--init -it --user ${docker_user} -v $(shell readlink -f ..):/go/katzenpost --network=host --rm -v $(cache_dir)/go:/go/ -v $(cache_dir)/root_cache:/root/.cache -e GORACE=history_size=7 -w /go/katzenpost/catshadow
run_docker_test=$(docker) run ${docker_args} $(image) go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -failfast -run 

test_version=v30

dockerdockertest:
	cd ../docker && make $(distro)_base.stamp
	$(run_docker_test)Docker

upgrade_test_use_saved:
	cd ../docker && make wait stop-memspool
	sleep 1
	cp -v testdata/$(test_version)/memspool.storage ../docker/voting_mixnet/servicenode1/
	cd ../docker && make start-memspool
	cp -v testdata/$(test_version)/*state testdata/ && \
	$(run_docker_test)UpgradeResume

upgrade_test_recreate:
	cd ../docker && make wait stop-memspool
	sleep 1
	rm -fv ../docker/voting_mixnet/servicenode1/memspool.storage
	cd ../docker && make start-memspool
	$(run_docker_test)UpgradeCreate
	cd ../docker && make stop-memspool
	sleep 1
	mkdir -p testdata/$(test_version)/
	cp -v ../docker/voting_mixnet/servicenode1/memspool.storage \
			testdata/*state testdata/$(test_version)/
	cd ../docker && make start-memspool

clean:
	rm -fv testdata/*state testdata/*.storage
