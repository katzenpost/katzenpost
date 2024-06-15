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

testdata/alice_state:
	cp -v testdata/$(test_version)/alice_state testdata/alice_state
testdata/bob_state:
	cp -v testdata/$(test_version)/bob_state testdata/bob_state
testdata/memspool.storage:
	cp -v testdata/$(test_version)/memspool.storage testdata/memspool.storage

testdata.stamp: testdata/alice_state testdata/bob_state testdata/memspool.storage
	cd ../docker && make stop && cp -v ../catshadow/testdata/memspool.storage voting_mixnet/servicenode1/ && make start wait
	touch testdata.stamp

upgrade_test: testdata.stamp
	$(docker) run ${docker_args} $(image) \
		sh -c 'cd /go/katzenpost/catshadow/; CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f GORACE=history_size=7 go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 0 -failfast -run Upgrade'

clean:
	rm -fv testdata/alice_state testdata/bob_state testdata/memspool.storage testdata.stamp
