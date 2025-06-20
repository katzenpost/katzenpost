// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	replicaCommon "github.com/katzenpost/katzenpost/replica/common"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/mkem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/pigeonhole"
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
	return new(commands.ReplicaMessageReply), nil
}

func (m *MockSession) Close() {
	// Mock implementation: no-op for testing purposes
}

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
	pkiScheme := signschemes.ByName(testPKIScheme)
	linkScheme := kemschemes.ByName("Xwing")
	replicaScheme := nikeschemes.ByName("CTIDH1024-X25519")
	sphinxScheme := nikeschemes.ByName("x25519")

	nrHops := 5
	payloadSize := 5000
	geometry := geo.GeometryFromUserForwardPayloadLength(sphinxScheme, payloadSize, true, nrHops)

	connRx, _ := net.Pipe()

	dname, err := os.MkdirTemp("", fmt.Sprintf("replica.testState_%d", os.Getpid()))
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
	err = cfg.FixupAndValidate(false)
	require.NoError(t, err)

	pkiWorker := &PKIWorker{
		replicas:   replicaCommon.NewReplicaMap(),
		WorkerBase: pki.NewWorkerBase(nil, nil), // No PKI client needed for test
	}

	server := &Server{
		identityPublicKey: pk,
		cfg:               cfg,
		PKIWorker:         pkiWorker,
	}

	linkpubkey, linkprivkey, err := linkScheme.GenerateKeyPair()
	require.NoError(t, err)
	server.linkKey = linkprivkey

	err = server.initDataDir()
	require.NoError(t, err)

	err = server.initLogging()
	require.NoError(t, err)

	epoch, _, _ := replicaCommon.ReplicaNow()
	server.envelopeKeys, err = NewEnvelopeKeys(replicaScheme, server.logBackend.GetLogger("envelope keys"), dname, epoch)
	require.NoError(t, err)

	st := &state{
		server: server,
		log:    server.LogBackend().GetLogger("state"),
	}
	server.state = st
	st.initDB()

	id := 0
	addr := "tcp://127.0.0.1:1234"
	listener, err := newListener(server, id, addr)
	require.NoError(t, err)

	listener.onNewConn(connRx)

	// Give the worker goroutine a moment to start and fail
	// since we're using a broken pipe connection
	time.Sleep(100 * time.Millisecond)

	listener.Lock()
	e := listener.conns.Front()
	inConn := e.Value.(*incomingConn)
	listener.Unlock()
	require.NotNil(t, inConn)

	// Wait a bit more to ensure the worker has failed and exited
	// before we start manipulating the connection state
	time.Sleep(50 * time.Millisecond)

	ad := make([]byte, 32)
	mockSession := &MockSession{
		pk: linkpubkey,
		ad: ad,
	}
	inConn.setSession(mockSession)

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

	boxid := &[bacap.BoxIDSize]byte{}
	_, err = rand.Reader.Read(boxid[:])
	require.NoError(t, err)

	sig := &[64]byte{}
	_, err = rand.Reader.Read(boxid[:])
	require.NoError(t, err)

	payload := make([]byte, 1000)
	// Convert wire command to trunnel type for testing
	wireWrite := &commands.ReplicaWrite{
		Cmds:      commands.NewStorageReplicaCommands(geometry, replicaScheme),
		BoxID:     boxid,
		Signature: sig,
		Payload:   payload,
	}
	trunnelWrite := pigeonhole.WireCommandToTrunnelReplicaWrite(wireWrite)
	reply := inConn.handleReplicaWrite(trunnelWrite)
	require.NotNil(t, reply)

	trunnelRead := &pigeonhole.ReplicaRead{}
	copy(trunnelRead.BoxID[:], boxid[:])
	reply2 := inConn.handleReplicaRead(trunnelRead)
	require.NotNil(t, reply2)

	// Generate valid cryptographic material for the ReplicaMessage
	senderEPubKey := make([]byte, commands.HybridKeySize(replicaScheme))
	_, err = rand.Reader.Read(senderEPubKey)
	require.NoError(t, err)

	dek := &[mkem.DEKSize]byte{}
	_, err = rand.Reader.Read(dek[:])
	require.NoError(t, err)

	ciphertext := make([]byte, 1000)
	_, err = rand.Reader.Read(ciphertext)
	require.NoError(t, err)

	replicaMessage := &commands.ReplicaMessage{
		Cmds: commands.NewStorageReplicaCommands(geometry, replicaScheme),
		Geo:  geometry,

		SenderEPubKey: senderEPubKey,
		DEK:           dek,
		Ciphertext:    ciphertext,
	}
	reply3 := inConn.handleReplicaMessage(replicaMessage)
	require.NotNil(t, reply3)
	// Expect an error reply since we're using invalid cryptographic material
	replicaReply3, ok := reply3.(*commands.ReplicaMessageReply)
	require.True(t, ok)
	require.NotEqual(t, uint8(0), replicaReply3.ErrorCode)

	// 30 seconds is too slow
	//inConn.Close()
	listener.Halt()
}
