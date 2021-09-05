
test:
	go test -v -race -timeout 0 -ldflags "-X github.com/katzenpost/core/epochtime.WarpedEpoch=true -X github.com/katzenpost/server/internal/pki.WarpedEpoch=true" .

lint:
	golint ./...

coverage-file:
	go test ./... -coverprofile=coverage.out

coverage-html:
	go tool cover -html=coverage.out
