
help:
	@echo "make targets:"
	@echo " test                        - run the integration test against a locally running mixnet (via docker/podman)"
	@echo

warped?=true
CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f"
ldflags="-X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/minclient/pki.WarpedEpoch=${warped}"

test:
	CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go test -v -race -timeout 0 -ldflags ${ldflags} -run TestDockerClientSendReceive


tests:
	CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go test -v -race -timeout 0 -ldflags ${ldflags}
