
.PHONY: all test clean server dirauth

all: server dirauth genconfig ping

server: clean
	cd server/cmd/server; CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go build

dirauth: clean
	cd authority/cmd/voting; CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go build

genconfig: clean
	cd genconfig; CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go build

ping: clean
	cd ping; CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go build

clean:
	rm -f server/cmd/server/server authority/cmd/voting/voting genconfig/genconfig ping/ping

test:
	CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go test -v -race -timeout 0 ./...

