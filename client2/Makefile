
help:
	@echo "make targets:"
	@echo " test                        - run the integration test against a locally running mixnet (via docker/podman)"
	@echo

warped?=true
CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f"
ldflags="-X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped}"

test:
	CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go test -v -race -timeout 0 -ldflags ${ldflags}

lint:
	golint ./...

coverage-file:
	CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go test ./... -coverprofile=coverage.out

coverage-html:
	CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go tool cover -html=coverage.out


dockerdockertest:
	$(docker) run ${docker_args} $(image) \
		sh -c 'cd /go/katzenpost/client/; GORACE=history_size=7 CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -run Docker'
