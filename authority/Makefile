warped?=false
CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f"
ldflags="-buildid= -X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/minclient/pki.WarpedEpoch=${warped}"

test:
	CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f" go test -race -cover -v ./...

lint:
	golint ./...

test-internal:
	CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f" go test -race -cover -v ./internal/...

test-voting:
	CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f" go test -race -cover -v ./voting/...

# no tests here
test-nonvoting:
	CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f" go test -race -cover -v ./nonvoting/...

coverage-file:
	CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f" go test ./... -coverprofile=coverage.out

coverage-html:
	CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f" go tool cover -html=coverage.out

cmd/voting/voting: clean
	cd cmd/voting && CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f" go build -trimpath -ldflags ${ldflags}

cmd/fetch/fetch: clean
	cd cmd/fetch && CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f" go build -trimpath -ldflags ${ldflags}

clean:
	rm -f cmd/fetch/fetch cmd/voting/voting cmd/nonvoting/nonvoting
