// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/replica/config"
)

type MockSession struct {
	ad []byte
	pk kem.PublicKey
}

func (m *MockSession) Initialize(conn net.Conn) error {
	return nil
}

func (m *MockSession) SendCommand(cmd commands.Command) error {
	return nil
}

func (m *MockSession) RecvCommand() (commands.Command, error) {
	return nil, nil
}

func (m *MockSession) Close() {}

func (m *MockSession) PeerCredentials() (*wire.PeerCredentials, error) {
	return &wire.PeerCredentials{
		AdditionalData: m.ad,
		PublicKey:      m.pk,
	}, nil
}

func (m *MockSession) ClockSkew() time.Duration {
	return time.Second
}

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

	linkpubkey, linkprivkey, err := linkScheme.GenerateKeyPair()
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

	ad := make([]byte, 32)
	inConn.w = &MockSession{
		pk: linkpubkey,
		ad: ad,
	}

	ids, err := listener.GetConnIdentities()
	require.NoError(t, err)
	require.Equal(t, len(ids), 0)

	listener.onInitializedConn(inConn)

	ids, err = listener.GetConnIdentities()
	require.NoError(t, err)
	require.Equal(t, len(ids), 1)

	listener.onClosedConn(inConn)

	ids, err = listener.GetConnIdentities()
	require.NoError(t, err)
	require.Equal(t, len(ids), 0)

	listener.onInitializedConn(inConn)
	err = listener.CloseOldConns(inConn)
	require.NoError(t, err)

	ids, err = listener.GetConnIdentities()
	require.NoError(t, err)
	require.Equal(t, len(ids), 0)

	replyCommand, ok := inConn.onReplicaCommand(new(commands.NoOp))
	require.True(t, ok)
	require.Nil(t, replyCommand)

	replyCommand, ok = inConn.onReplicaCommand(new(commands.Disconnect))
	require.False(t, ok)
	require.Nil(t, replyCommand)

	//replyCommand, ok = inConn.onReplicaCommand(new(commands.ReplicaWrite))
	//require.True(t, ok)
	//require.NotNil(t, replyCommand)

	//replyCommand, ok = inConn.onReplicaCommand(new(commands.ReplicaMessage))
	//require.True(t, ok)
	//require.NotNil(t, replyCommand)

	replyCommand, ok = inConn.onReplicaCommand(new(commands.Consensus))
	require.False(t, ok)
	require.Nil(t, replyCommand)

	// 30 seconds is too slow
	//inConn.Close()
	listener.Halt()
}
