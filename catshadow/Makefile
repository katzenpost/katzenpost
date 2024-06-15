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

upgrade_test_use_saved: testdata/$(test_version)/alice1_state testdata/$(test_version)/bob1_state testdata/$(test_version)/memspool.storage
	cd ../docker && make stop clean-local && mkdir -p voting_mixnet/servicenode1/ && cp -v ../catshadow/testdata/$(test_version)/memspool.storage voting_mixnet/servicenode1/ && make start wait
	cp -v testdata/$(test_version)/*state testdata/
	$(docker) run ${docker_args} $(image) \
		sh -c 'cd /go/katzenpost/catshadow/; GORACE=history_size=7 go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 0 -failfast -run UpgradeResume'

upgrade_test_recreate:
	mkdir -p testdata/$(test_version)
	$(docker) run ${docker_args} $(image) \
		sh -c 'cd /go/katzenpost/catshadow/; GORACE=history_size=7 go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 0 -failfast -run UpgradeCreate'
	cd ../docker && make stop && cd ../catshadow && mv -v ../docker/voting_mixnet/servicenode1/memspool.storage testdata/*state testdata/$(test_version)/

clean:
	rm -fv testdata/*state testdata/*.storage
