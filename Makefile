
.PHONY: all test sphincsplus clean server dirauth genconfig ping

all: server dirauth genconfig ping

server:
	cd server/cmd/server; go build

dirauth:
	cd authority/cmd/voting; go build

genconfig:
	cd genconfig; go build

ping:
	cd ping; go build

clean:
	rm -f server/cmd/server/server authority/cmd/voting/voting genconfig/genconfig ping/ping

sphincsplus:
	cd sphincsplus/ref && go test -v -race -timeout 0 ./...

test:
	go test -v -race -timeout 0 ./...

