test:
	go test -cover -v ./...

lint:
	golint ./...

coverage-file:
	go test ./... -coverprofile=coverage.out

coverage-html:
	go tool cover -html=coverage.out

bench:
	go test ./... -run=XXX -bench=.
