// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

type wireUploadFixture struct {
	*uploadFixture
	kem   kem.Scheme
	wg    sync.WaitGroup
	mu    sync.Mutex
	conns []net.Conn
}

func newWireUploadFixture(t *testing.T, kind string, perPeer int) *wireUploadFixture {
	t.Helper()
	const wireKEM = "Xwing"
	f := newUploadFixture(t, testSchemeName)
	kemScheme := kemschemes.ByName(wireKEM)
	require.NotNil(t, kemScheme)
	respIDPub, _, err := signschemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	_, respLinkPriv, err := kemScheme.GenerateKeyPair()
	require.NoError(t, err)
	lb, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	cfg := f.srv.cfg.Server
	cfg.WireKEMScheme = wireKEM
	cfg.HandshakeTimeoutSec = 30
	cfg.ResponseTimeoutSec = 30
	cfg.KeepaliveTimeoutSec = 120
	cfg.MaxConnsPerPeer = perPeer
	f.srv.identityPublicKey = respIDPub
	f.srv.linkKey = respLinkPriv
	f.srv.logBackend = lb
	f.srv.haltedCh = make(chan interface{})
	f.srv.connSem = make(chan struct{}, 64)

	w := &wireUploadFixture{uploadFixture: f, kem: kemScheme}
	t.Cleanup(func() {
		w.mu.Lock()
		for _, c := range w.conns {
			_ = c.Close()
		}
		w.mu.Unlock()
		w.wg.Wait()
	})
	if kind == "replica" {
		delete(w.srv.state.authorizedMixes, w.idHash)
	} else {
		delete(w.srv.state.authorizedReplicaNodes, w.idHash)
	}
	return w
}

func (w *wireUploadFixture) newLinkKey(t *testing.T) (kem.PrivateKey, []byte) {
	t.Helper()
	_, priv, err := w.kem.GenerateKeyPair()
	require.NoError(t, err)
	blob, err := priv.Public().MarshalBinary()
	require.NoError(t, err)
	return priv, blob
}

func (w *wireUploadFixture) dial(t *testing.T, linkPriv kem.PrivateKey) (*wire.Session, error) {
	t.Helper()
	srvConn, cliConn := net.Pipe()
	w.mu.Lock()
	w.conns = append(w.conns, srvConn, cliConn)
	w.mu.Unlock()
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		w.srv.handleConn(srvConn)
	}()
	cli, err := wire.NewPKISession(&wire.SessionConfig{
		KEMScheme:          w.kem,
		PKISignatureScheme: signschemes.ByName(testSchemeName),
		Authenticator:      acceptAuthenticator{},
		AdditionalData:     w.idHash[:],
		AuthenticationKey:  linkPriv,
		RandomReader:       rand.Reader,
	}, true)
	require.NoError(t, err)
	hsErr := make(chan error, 1)
	go func() { hsErr <- cli.Initialize(context.Background(), cliConn) }()
	select {
	case err := <-hsErr:
		return cli, err
	case <-time.After(30 * time.Second):
		t.Fatal("handshake hung")
	}
	return nil, nil
}

func (w *wireUploadFixture) mixUpload(t *testing.T, epoch uint64, linkKey []byte) []byte {
	t.Helper()
	idKey, err := w.pub.MarshalBinary()
	require.NoError(t, err)
	up := &pki.SignedUpload{MixDescriptor: &pki.MixDescriptor{
		Name:        "mix1",
		Epoch:       epoch,
		IdentityKey: idKey,
		LinkKey:     linkKey,
		MixKeys:     map[uint64][]byte{epoch: {1}},
		Addresses:   map[string][]string{"tcp": {"tcp://127.0.0.1:1"}},
	}}
	require.NoError(t, up.Sign(w.priv, w.pub))
	raw, err := up.Marshal()
	require.NoError(t, err)
	return raw
}

func (w *wireUploadFixture) replicaUpload(t *testing.T, epoch uint64, linkKey []byte) []byte {
	t.Helper()
	idKey, err := w.pub.MarshalBinary()
	require.NoError(t, err)
	up := &pki.SignedReplicaUpload{ReplicaDescriptor: &pki.ReplicaDescriptor{
		Name:         "replica1",
		ReplicaID:    1,
		Epoch:        epoch,
		IdentityKey:  idKey,
		LinkKey:      linkKey,
		EnvelopeKeys: map[uint64][]byte{1: {1}},
		Addresses:    map[string][]string{"tcp": {"tcp://127.0.0.1:1"}},
	}}
	require.NoError(t, up.Sign(w.priv, w.pub))
	raw, err := up.Marshal()
	require.NoError(t, err)
	return raw
}

func roundTripStatus(t *testing.T, s *wire.Session, cmd commands.Command) (uint8, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.SendCommand(ctx, cmd); err != nil {
		return 0, err
	}
	resp, err := s.RecvCommand(ctx)
	if err != nil {
		return 0, err
	}
	switch r := resp.(type) {
	case *commands.PostDescriptorStatus:
		return r.ErrorCode, nil
	case *commands.PostReplicaDescriptorStatus:
		return r.ErrorCode, nil
	case *commands.Consensus:
		return r.ErrorCode, nil
	}
	t.Fatalf("unexpected response %T", resp)
	return 0, nil
}

func (w *wireUploadFixture) post(t *testing.T, kind string, linkPriv kem.PrivateKey, epoch uint64, descLinkKey []byte) (uint8, error) {
	t.Helper()
	s, err := w.dial(t, linkPriv)
	if err != nil {
		return 0, err
	}
	var cmd commands.Command = &commands.PostDescriptor{Epoch: epoch, Payload: w.mixUpload(t, epoch, descLinkKey)}
	if kind == "replica" {
		cmd = &commands.PostReplicaDescriptor{Epoch: epoch, Payload: w.replicaUpload(t, epoch, descLinkKey)}
	}
	return roundTripStatus(t, s, cmd)
}

func TestUploadDescriptorLinkKeyBoundToSession(t *testing.T) {
	for _, kind := range []string{"mix", "replica"} {
		t.Run(kind, func(t *testing.T) {
			t.Run("mismatch", func(t *testing.T) {
				w := newWireUploadFixture(t, kind, 8)
				sessionKey, _ := w.newLinkKey(t)
				_, otherBlob := w.newLinkKey(t)
				code, err := w.post(t, kind, sessionKey, w.epoch, otherBlob)
				require.NoError(t, err)
				require.Equal(t, uint8(commands.DescriptorForbidden), code,
					"%s descriptor whose LinkKey is not the session link key was not rejected", kind)
			})
			t.Run("match", func(t *testing.T) {
				w := newWireUploadFixture(t, kind, 8)
				sessionKey, sessionBlob := w.newLinkKey(t)
				code, err := w.post(t, kind, sessionKey, w.epoch, sessionBlob)
				require.NoError(t, err)
				require.Equal(t, uint8(commands.DescriptorOk), code)
			})
		})
	}
}
