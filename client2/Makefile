warped?=true
ldflags="-extldflags '-Wl,-z,stack-size=0x1F40000' -buildid= -X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped}"

uid=$(shell [ "$$SUDO_UID" != "" ] && echo "$$SUDO_UID" || id -u)
gid=$(shell [ "$$SUDO_GID" != "" ] && echo "$$SUDO_GID" || id -g)
docker_user?=$(shell if echo ${docker}|grep -q podman; then echo 0:0; else echo ${uid}:${gid}; fi)
docker=$(shell if which podman|grep -q .; then echo podman; else echo docker; fi)
distro=alpine
image=localhost/katzenpost-$(distro)_base
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

dockertest_channel_basics:
	cd ../docker && make $(distro)_base.stamp
	$(docker) run -w /go/katzenpost/client2 ${docker_args} $(image) \
		go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -run "TestChannelAPIBasics"

dockertest_channel_close:
	cd ../docker && make $(distro)_base.stamp
	$(docker) run -w /go/katzenpost/client2 ${docker_args} $(image) \
		go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -run "TestChannelClose"

dockertest_resume_write_channel:
	cd ../docker && make $(distro)_base.stamp
	$(docker) run -w /go/katzenpost/client2 ${docker_args} $(image) \
		go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -run "TestResumeWriteChannel"

dockertest_resume_write_channel_query:
	cd ../docker && make $(distro)_base.stamp
	$(docker) run -w /go/katzenpost/client2 ${docker_args} $(image) \
		go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -run "TestResumeWriteChannelQuery"

dockertest_resume_read_channel:
	cd ../docker && make $(distro)_base.stamp
	$(docker) run -w /go/katzenpost/client2 ${docker_args} $(image) \
		go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -run "TestResumeReadChannel"

dockertest_resume_read_channel_query:
	cd ../docker && make $(distro)_base.stamp
	$(docker) run -w /go/katzenpost/client2 ${docker_args} $(image) \
		go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -run "TestResumeReadChannelQuery"

all_channels_tests: dockertest_channel_basics dockertest_channel_close dockertest_resume_write_channel dockertest_resume_write_channel_query dockertest_resume_read_channel dockertest_resume_read_channel_query

warpedclientdaemon:
	cd ../cmd/kpclientd; go build -ldflags ${ldflags}

clientdaemon:
	cd ../cmd/kpclientd; go build
