// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/pigeonhole"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

type trackedNikeKey struct {
	nike.PrivateKey
	mu        sync.Mutex
	reset     bool
	handedOut [][]byte
}

func (k *trackedNikeKey) Reset() {
	k.mu.Lock()
	k.reset = true
	k.mu.Unlock()
	k.PrivateKey.Reset()
}

func (k *trackedNikeKey) Bytes() []byte {
	b := k.PrivateKey.Bytes()
	k.mu.Lock()
	k.handedOut = append(k.handedOut, b)
	k.mu.Unlock()
	return b
}

type trackingNikeScheme struct {
	nike.Scheme
	mu   sync.Mutex
	keys []*trackedNikeKey
}

func (s *trackingNikeScheme) track(p nike.PrivateKey) nike.PrivateKey {
	k := &trackedNikeKey{PrivateKey: p}
	s.mu.Lock()
	s.keys = append(s.keys, k)
	s.mu.Unlock()
	return k
}

func untrackNikeKey(p nike.PrivateKey) nike.PrivateKey {
	if k, ok := p.(*trackedNikeKey); ok {
		return k.PrivateKey
	}
	return p
}

func (s *trackingNikeScheme) GenerateKeyPair() (nike.PublicKey, nike.PrivateKey, error) {
	pub, priv, err := s.Scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	return pub, s.track(priv), nil
}

func (s *trackingNikeScheme) UnmarshalBinaryPrivateKey(b []byte) (nike.PrivateKey, error) {
	priv, err := s.Scheme.UnmarshalBinaryPrivateKey(b)
	if err != nil {
		return nil, err
	}
	return s.track(priv), nil
}

func (s *trackingNikeScheme) DeriveSecret(p nike.PrivateKey, pub nike.PublicKey) []byte {
	return s.Scheme.DeriveSecret(untrackNikeKey(p), pub)
}

func (s *trackingNikeScheme) DerivePublicKey(p nike.PrivateKey) nike.PublicKey {
	return s.Scheme.DerivePublicKey(untrackNikeKey(p))
}

func (s *trackingNikeScheme) requireAllWiped(t *testing.T, what string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.keys, "%s generated no tracked key", what)
	for _, k := range s.keys {
		k.mu.Lock()
		require.True(t, k.reset, "%s left an ephemeral MKEM private key unwiped", what)
		for _, b := range k.handedOut {
			require.Equal(t, make([]byte, len(b)), b, "%s left a copy of an ephemeral MKEM private key unwiped", what)
		}
		k.mu.Unlock()
	}
}

func swapClientMKEMScheme(t *testing.T) *trackingNikeScheme {
	s := &trackingNikeScheme{Scheme: replicaCommon.NikeScheme}
	oldNike, oldMKEM := replicaCommon.NikeScheme, replicaCommon.MKEMNikeScheme
	replicaCommon.NikeScheme = s
	replicaCommon.MKEMNikeScheme = mkem.NewScheme(s)
	t.Cleanup(func() {
		replicaCommon.NikeScheme = oldNike
		replicaCommon.MKEMNikeScheme = oldMKEM
	})
	return s
}

func waitForResponse(t *testing.T, responseCh chan *Response) *Response {
	t.Helper()
	select {
	case resp := <-responseCh:
		return resp
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for the response")
		return nil
	}
}

func TestBuildCourierEnvelopeWipesEphemeralKey(t *testing.T) {
	d, _, _ := setupDaemonWithMockConn(t)
	doc := createMockPKIDocument(t)
	s := swapClientMKEMScheme(t)

	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	tombstone, err := pigeonhole.NewTombstone(writeCap.Start())
	require.NoError(t, err)

	replicaEpoch := replicaCommon.ConvertNormalToReplicaEpoch(doc.Epoch)
	_, err = d.buildCourierEnvelope(doc, replicaEpoch, &tombstone.BoxID, writeInnerMessage(tombstone))
	require.NoError(t, err)

	s.requireAllWiped(t, "buildCourierEnvelope")
}

func TestEncryptReadWipesEphemeralKey(t *testing.T) {
	d, appID, responseCh := setupDaemonWithMockConn(t)
	s := swapClientMKEMScheme(t)

	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	d.encryptRead(&Request{
		AppID: appID,
		EncryptRead: &thin.EncryptRead{
			QueryID:         &[thin.QueryIDLength]byte{1},
			ReadCap:         writeCap.ReadCap(),
			MessageBoxIndex: writeCap.GetMessageBoxIndex(),
		},
	})
	resp := waitForResponse(t, responseCh)
	require.NotNil(t, resp.EncryptReadReply)
	require.Equal(t, thin.ThinClientSuccess, resp.EncryptReadReply.ErrorCode)

	s.requireAllWiped(t, "encryptRead")
}

func TestEncryptWriteWipesEphemeralKey(t *testing.T) {
	d, appID, responseCh := setupDaemonWithMockConn(t)
	s := swapClientMKEMScheme(t)

	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	d.encryptWrite(&Request{
		AppID: appID,
		EncryptWrite: &thin.EncryptWrite{
			QueryID:         &[thin.QueryIDLength]byte{2},
			Plaintext:       []byte("hello"),
			WriteCap:        writeCap,
			MessageBoxIndex: writeCap.GetMessageBoxIndex(),
		},
	})
	resp := waitForResponse(t, responseCh)
	require.NotNil(t, resp.EncryptWriteReply)
	require.Equal(t, thin.ThinClientSuccess, resp.EncryptWriteReply.ErrorCode)

	s.requireAllWiped(t, "encryptWrite")
}

func TestDecryptPigeonholeReplyWipesEnvelopeKey(t *testing.T) {
	d, _, _ := setupDaemonWithMockConn(t)
	_, priv, err := replicaCommon.NikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	desc, err := (&EnvelopeDescriptor{
		Epoch:       replicaEpoch,
		ReplicaNums: [2]uint8{0, 1},
		EnvelopeKey: priv.Bytes(),
	}).Bytes()
	require.NoError(t, err)
	s := swapClientMKEMScheme(t)

	_, err = d.decryptPigeonholeReply(&ARQMessage{EnvelopeDescriptor: desc}, &pigeonhole.CourierEnvelopeReply{Payload: make([]byte, 128)})
	require.Error(t, err)

	s.requireAllWiped(t, "decryptPigeonholeReply")
}
