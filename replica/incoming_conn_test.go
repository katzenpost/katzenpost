// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"fmt"
	"net"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/replica/config"
)

func TestIncomingConn(t *testing.T) {
	pkiScheme := signschemes.ByName("Ed25519 Sphincs+")
	linkScheme := kemschemes.ByName("Xwing")
	replicaScheme := nikeschemes.ByName("x25519")
	sphinxScheme := nikeschemes.ByName("x25519")

	nrHops := 5
	payloadSize := 5000
	geometry := geo.GeometryFromUserForwardPayloadLength(sphinxScheme, payloadSize, true, nrHops)

	connRx, _ := net.Pipe()

	dname, err := os.MkdirTemp("", fmt.Sprintf("replica.testState %d", os.Getpid()))
	require.NoError(t, err)
	defer os.RemoveAll(dname)

	pk, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)

	cfg := &config.Config{
		PKI:        &config.PKI{},
		Identifier: "replica1",
		Logging: &config.Logging{
			Disable: false,
			File:    "",
			Level:   "DEBUG",
		},
		DataDir:            dname,
		SphinxGeometry:     geometry,
		PKISignatureScheme: pkiScheme.Name(),
		ReplicaNIKEScheme:  replicaScheme.Name(),
		WireKEMScheme:      linkScheme.Name(),
		Addresses:          []string{"tcp://127.0.0.1:34394"},
	}

	server := &Server{
		identityPublicKey: pk,
		cfg:               cfg,
		pkiWorker: &PKIWorker{
			replicas:      newReplicaMap(),
			lock:          new(sync.RWMutex),
			docs:          make(map[uint64]*pki.Document),
			rawDocs:       make(map[uint64][]byte),
			failedFetches: make(map[uint64]error),
		},
	}

	_, linkprivkey, err := linkScheme.GenerateKeyPair()
	require.NoError(t, err)
	server.linkKey = linkprivkey

	err = server.initDataDir()
	require.NoError(t, err)

	err = server.initLogging()
	require.NoError(t, err)

	id := 0
	addr := "tcp://127.0.0.1:1234"
	listener, err := newListener(server, id, addr)
	require.NoError(t, err)

	listener.onNewConn(connRx)

	listener.Lock()
	e := listener.conns.Front()
	inConn := e.Value.(*incomingConn)
	listener.Unlock()
	require.NotNil(t, inConn)

	//inConn.Close()
	//listener.Halt()
}
