test:
	go test -v -race -timeout 0 -ldflags "-X github.com/katzenpost/core/epochtime.WarpedEpoch=true -X github.com/katzenpost/server/internal/pki.WarpedEpoch=true" .

lint:
	golint ./...

coverage-file:
	go test ./... -coverprofile=coverage.out

coverage-html:
	go tool cover -html=coverage.out


dockerdockertest:
	docker run --network=host --rm -it -v $(shell readlink -f ..):/go/katzenpost/ katzenpost/deps \
		bash -c 'cd /go/katzenpost/client/; GORACE=history_size=7 go test -tags=docker_test -race -v -run Docker'
