// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
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

type replyingConnector struct {
	fakeConnector
	courier *Courier
}

func (c *replyingConnector) DispatchMessage(dest uint8, msg *commands.ReplicaMessage) error {
	go c.courier.HandleReply(&commands.ReplicaMessageReply{
		EnvelopeHash: msg.EnvelopeHash(),
		ReplicaID:    dest,
		ErrorCode:    pigeonhole.ReplicaSuccess,
	})
	return nil
}

func TestTryReadFromShardReplicaWipesEphemeralKey(t *testing.T) {
	courier := createTestCourier(t)
	conn := newFakeConnector()
	conn.sendErr = errors.New("no route to replica")
	courier.server.connector = conn
	s := &trackingNikeScheme{Scheme: courier.envelopeScheme}
	courier.envelopeScheme = s

	shardPub, _, err := s.Scheme.GenerateKeyPair()
	require.NoError(t, err)
	_, _, err = courier.tryReadFromShardReplica(&[bacap.BoxIDSize]byte{1}, &pki.ReplicaDescriptor{Name: "replica-0", ReplicaID: 0}, shardPub)
	require.Error(t, err)

	s.requireAllWiped(t, "tryReadFromShardReplica")
}

func TestWriteTombstonesToTempChannelWipesEphemeralKey(t *testing.T) {
	courier := createTestCourier(t)
	courier.server.PKI.Halt()
	courier.server.connector = &replyingConnector{fakeConnector: *newFakeConnector(), courier: courier}
	s := &trackingNikeScheme{Scheme: courier.envelopeScheme}
	courier.envelopeScheme = s

	now, _, _ := epochtime.Now()
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	doc := &pki.Document{Epoch: now}
	for i := 0; i < 2; i++ {
		pub, _, err := s.Scheme.GenerateKeyPair()
		require.NoError(t, err)
		idKey := make([]byte, 32)
		_, err = rand.Reader.Read(idKey)
		require.NoError(t, err)
		doc.StorageReplicas = append(doc.StorageReplicas, &pki.ReplicaDescriptor{
			Name:         fmt.Sprintf("replica-%d", i),
			ReplicaID:    uint8(i),
			IdentityKey:  idKey,
			EnvelopeKeys: map[uint64][]byte{replicaEpoch: pub.Bytes()},
		})
		doc.ConfiguredReplicaIdentityKeys = append(doc.ConfiguredReplicaIdentityKeys, idKey)
	}
	courier.server.PKI.SetDocumentForEpoch(now, doc, []byte("doc"))

	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	tombstone, err := pigeonhole.NewTombstone(writeCap.Start())
	require.NoError(t, err)
	courier.writeTombstonesToTempChannel(writeCap, [][bacap.BoxIDSize]byte{tombstone.BoxID})

	s.requireAllWiped(t, "writeTombstonesToTempChannel")
}
