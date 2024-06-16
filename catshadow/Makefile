warped?=true
CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f"
ldflags="-X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/minclient/pki.WarpedEpoch=${warped}"
uid=$(shell [ "$$SUDO_UID" != "" ] && echo "$$SUDO_UID" || id -u)
gid=$(shell [ "$$SUDO_GID" != "" ] && echo "$$SUDO_GID" || id -g)
docker_user?=$(shell if echo ${docker}|grep -q podman; then echo 0:0; else echo ${uid}:${gid}; fi)
docker=$(shell if which podman|grep -q .; then echo podman; else echo docker; fi)
distro=alpine
image=katzenpost-$(distro)_go_mod
docker_args=--user ${docker_user} -v $(shell readlink -f ..):/go/katzenpost -e GOCACHE=/tmp/gocache --network=host --rm

test_version=v30

dockerdockertest:
	$(docker) run ${docker_args} $(image) \
		sh -c 'cd /go/katzenpost/catshadow/; CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f GORACE=history_size=7 go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 0 -failfast -run Docker'

upgrade_test_use_saved:
	# we clean-local here because there is a bug where the network restarts and
	# gets consensus but loses it in the next one, so the wait command lets the
	# test run while consensus is lost.
	cd ../docker && make stop clean-local && \
		mkdir -p voting_mixnet/servicenode1/ && \
		chmod 700 voting_mixnet/servicenode1/ && \
		cp -v ../catshadow/testdata/$(test_version)/memspool.storage voting_mixnet/servicenode1/ && \
		make start wait
	cp -v testdata/$(test_version)/*state testdata/
	$(docker) run ${docker_args} $(image) \
		sh -c 'cd /go/katzenpost/catshadow/; CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f GORACE=history_size=7 go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 0 -failfast -run UpgradeResume'

upgrade_test_recreate:
	cd ../docker && make clean-local start wait
	mkdir -p testdata/$(test_version)
	$(docker) run ${docker_args} $(image) \
		sh -c 'cd /go/katzenpost/catshadow/; CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f GORACE=history_size=7 go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 0 -failfast -run UpgradeCreate'
	cd ../docker && make stop && cd ../catshadow && mv -v ../docker/voting_mixnet/servicenode1/memspool.storage testdata/*state testdata/$(test_version)/

clean:
	rm -fv testdata/*state testdata/*.storage
