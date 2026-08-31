ldflags="-buildid="

all: clean client server

client:
	cd ../../cmd/http-proxy-client && go build -trimpath -ldflags ${ldflags}

server:
	cd ../../cmd/http-proxy-server && go build -trimpath -ldflags ${ldflags}
clean:
	rm -f ../../cmd/http-proxy-client/http-proxy-client ../../cmd/http-proxy-server/http-proxy-server
