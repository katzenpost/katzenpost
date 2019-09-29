test:
	go test -cover -v ./...

cover:
	go test . -coverprofile=coverage.out
	go tool cover -html=coverage.out
