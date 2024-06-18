warped?=false
ldflags="-buildid= -X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped}"

all: clean client/client server/server

client/client:
	cd client && go build -trimpath -ldflags ${ldflags}

server/server:
	cd server && go build -trimpath -ldflags ${ldflags}
clean:
	rm -f client/client server/server
