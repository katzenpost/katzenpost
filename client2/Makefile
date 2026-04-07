warped?=true
ldflags="-extldflags '-Wl,-z,stack-size=0x1F40000' -buildid= -X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped}"

uid=$(shell [ "$$SUDO_UID" != "" ] && echo "$$SUDO_UID" || id -u)
gid=$(shell [ "$$SUDO_GID" != "" ] && echo "$$SUDO_GID" || id -g)
docker_user?=$(shell if echo ${docker}|grep -q podman; then echo 0:0; else echo ${uid}:${gid}; fi)
docker=$(shell if which podman|grep -q .; then echo podman; else echo docker; fi)
distro=alpine
ifdef ACT
image=katzenpost-$(distro)_base
else
image=localhost/katzenpost-$(distro)_base
endif
cache_dir=$(shell readlink -f ../docker)/cache
docker_args=--init -it --user ${docker_user} -v $(shell readlink -f ..):/go/katzenpost --network=host --rm -v $(cache_dir)/go:/go/ -e GORACE=history_size=7 -e GOCACHE=/go/cache

test:
	go test -v -race -timeout 0 -ldflags ${ldflags} .

lint:
	golint ./...

coverage-file:
	go test ./... -coverprofile=coverage.out

coverage-html:
	go tool cover -html=coverage.out

dockertest-legacy:
	cd ../docker && make $(distro)_base.stamp
	$(docker) run -w /go/katzenpost/client2 ${docker_args} $(image) \
		go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -run "TestLegacyTests"

dockertest_new_pigeonhole_alice_sends_bob:
	cd ../docker && make $(distro)_base.stamp
	$(docker) run -w /go/katzenpost/client2 ${docker_args} $(image) \
		go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -run "TestNewPigeonholeAPIAliceSendsBob"

dockertest_new_pigeonhole_multiple_messages:
	cd ../docker && make $(distro)_base.stamp
	$(docker) run -w /go/katzenpost/client2 ${docker_args} $(image) \
		go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -run "TestNewPigeonholeAPIMultipleMessages$$"

dockertest_new_pigeonhole_multiple_messages_bulk:
	cd ../docker && make $(distro)_base.stamp
	$(docker) run -w /go/katzenpost/client2 ${docker_args} $(image) \
		go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -run "TestNewPigeonholeAPIMultipleMessagesBulk"

dockertest_copy_command:
	cd ../docker && make $(distro)_base.stamp
	$(docker) run -w /go/katzenpost/client2 ${docker_args} $(image) \
		go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -run "TestCreateCourierEnvelopesFromPayload"

dockertest_multichannel:
	cd ../docker && make $(distro)_base.stamp
	$(docker) run -w /go/katzenpost/client2 ${docker_args} $(image) \
		go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -run "TestCopyCommandMultiChannel$$"

dockertest_multichannel_efficient:
	cd ../docker && make $(distro)_base.stamp
	$(docker) run -w /go/katzenpost/client2 ${docker_args} $(image) \
		go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -run "TestCopyCommandMultiChannelEfficient"

dockertest_tombstone_box:
	cd ../docker && make $(distro)_base.stamp
	$(docker) run -w /go/katzenpost/client2 ${docker_args} $(image) \
		go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -run "TestTombstoning"

dockertest_tombstone_range:
	cd ../docker && make $(distro)_base.stamp
	$(docker) run -w /go/katzenpost/client2 ${docker_args} $(image) \
		go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -run "TestTombstoneRange"

dockertest_box_id_not_found:
	cd ../docker && make $(distro)_base.stamp
	$(docker) run -w /go/katzenpost/client2 ${docker_args} $(image) \
		go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -run "TestBoxIDNotFoundError"

dockertest_box_already_exists:
	cd ../docker && make $(distro)_base.stamp
	$(docker) run -w /go/katzenpost/client2 ${docker_args} $(image) \
		go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -run "TestBoxAlreadyExistsError"

dockertest_read_before_write:
	cd ../docker && make $(distro)_base.stamp
	$(docker) run -w /go/katzenpost/client2 ${docker_args} $(image) \
		go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -run "TestReadBeforeWrite"


dockertest_nested_copy:
	cd ../docker && make $(distro)_base.stamp
	$(docker) run -w /go/katzenpost/client2 ${docker_args} $(image) \
		go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -run "TestNestedCopyCommands"

all_new_pigeonhole_tests: dockertest_new_pigeonhole_alice_sends_bob dockertest_new_pigeonhole_multiple_messages dockertest_new_pigeonhole_multiple_messages_bulk dockertest_copy_command dockertest_multichannel dockertest_multichannel_efficient dockertest_tombstone_box dockertest_tombstone_range dockertest_box_id_not_found dockertest_box_already_exists dockertest_read_before_write dockertest_nested_copy

warpedclientdaemon:
	cd ../cmd/kpclientd; go build -ldflags ${ldflags}

clientdaemon:
	cd ../cmd/kpclientd; go build
