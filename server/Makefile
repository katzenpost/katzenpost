warped?=false
ldflags="-buildid= -X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped}"

testnet-build:
	cd cmd/server ; go build -trimpath -ldflags ${ldflags}
	cd ../memspool/server/cmd/memspool ; go build -trimpath -ldflags ${ldflags}
	cd ../pigeonhole/server/cmd/pigeonhole; go build -ldflags ${ldflags}
	cd ../reunion/servers/reunion_katzenpost_server ; go build -trimpath -ldflags ${ldflags}
	cd ../panda/server/cmd/panda_server ; go build -trimpath -ldflags ${ldflags}
	cd ../server_plugins/cbor_plugins/echo-go ; go build -trimpath -o echo_server -ldflags ${ldflags}

testnet-install:
	mv /go/katzenpost/server/cmd/server/server /$(net_name)/server.$(distro)
	mv /go/katzenpost/memspool/server/cmd/memspool/memspool /$(net_name)/memspool.$(distro)
	mv /go/katzenpost/pigeonhole/server/cmd/pigeonhole/pigeonhole /$(net_name)/pigeonhole.$(distro)
	mv /go/katzenpost/reunion/servers/reunion_katzenpost_server/reunion_katzenpost_server /$(net_name)/reunion_katzenpost_server.$(distro)
	mv /go/katzenpost/panda/server/cmd/panda_server/panda_server /$(net_name)/panda_server.$(distro)
	mv /go/katzenpost/server_plugins/cbor_plugins/echo-go/echo_server /$(net_name)/echo_server.$(distro)
