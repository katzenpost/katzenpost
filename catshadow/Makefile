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

upgrade_test_use_saved: testdata/$(test_version)/alice_state testdata/$(test_version)/bob_state testdata/$(test_version)/memspool.storage
	cd ../docker && make stop && cp -v ../catshadow/testdata/$(test_version)/memspool.storage voting_mixnet/servicenode1/ && make start wait
	cp -v testdata/$(test_version)/bob_state testdata/bob_state
	cp -v testdata/$(test_version)/alice_state testdata/alice_state
	$(docker) run ${docker_args} $(image) \
		sh -c 'cd /go/katzenpost/catshadow/; CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f GORACE=history_size=7 go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 0 -failfast -run Upgrade'
	rm -fv testdata/mempool.storage

upgrade_test_recreate:
	rm -fv testdata/alice_state testdata/bob_state
	mkdir -p testdata/$(test_version)
	$(docker) run ${docker_args} $(image) \
		sh -c 'cd /go/katzenpost/catshadow/; CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f GORACE=history_size=7 go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 0 -failfast -run Upgrade'
	cd ../docker && make stop && cd ../catshadow && mv -v ../docker/voting_mixnet/servicenode1/memspool.storage testdata/alice_state testdata/bob_state testdata/$(test_version)/

clean:
	rm -fv testdata/alice_state testdata/bob_state testdata/mempool.storage
