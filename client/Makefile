warped?=false
ldflags="-X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/minclient/pki.WarpedEpoch=${warped}"

test:
	go test -v -race -timeout 0 -ldflags ${ldflags} .

lint:
	golint ./...

coverage-file:
	go test ./... -coverprofile=coverage.out

coverage-html:
	go tool cover -html=coverage.out


dockerdockertest:
	docker run --network=host --rm -it -v $(shell readlink -f ..):/go/katzenpost/ katzenpost/deps \
		bash -c 'cd /go/katzenpost/client/; GORACE=history_size=7 go test -ldflags ${ldflags} -tags=docker_test -race -v -run Docker'
