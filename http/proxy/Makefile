warped?=false
ldflags="-buildid= "

all: clean client/client server/server

client/client:
	cd client && go build -trimpath -ldflags ${ldflags}

server/server:
	cd server && go build -trimpath -ldflags ${ldflags}
clean:
	rm -f client/client server/server
