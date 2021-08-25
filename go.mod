module github.com/katzenpost/server

go 1.13

require (
	git.schwanenlied.me/yawning/aez.git v0.0.0-20180408160647-ec7426b44926
	git.schwanenlied.me/yawning/avl.git v0.0.0-20180224045358-04c7c776e391
	git.schwanenlied.me/yawning/bloom.git v0.0.0-20181019144233-44d6c5c71ed1
	github.com/BurntSushi/toml v0.3.1
	github.com/coreos/bbolt v1.3.3
	github.com/dchest/siphash v1.2.1 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/fxamacker/cbor/v2 v2.2.0
	github.com/jackc/pgx v3.6.2+incompatible
	github.com/katzenpost/authority v0.0.15
	github.com/katzenpost/core v0.0.15-0.20210825020348-f927548df5f7
	github.com/katzenpost/noise v0.0.2 // indirect
	github.com/prometheus/client_golang v1.6.0
	github.com/stretchr/testify v1.4.0
	github.com/ugorji/go/codec v1.1.7
	go.etcd.io/bbolt v1.3.4
	golang.org/x/net v0.0.0-20200501053045-e0ff5e5a1de5
	golang.org/x/text v0.3.2
	gopkg.in/eapache/channels.v1 v1.1.0
	gopkg.in/op/go-logging.v1 v1.0.0-20160211212156-b2cb9fa56473
)
