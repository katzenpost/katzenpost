// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"

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

func TestProxyToShardFailureWipesEphemeralKey(t *testing.T) {
	env := setupSemaScopeTestServer(t)
	s := &trackingNikeScheme{Scheme: replicaCommon.NikeScheme}
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()

	_, key, _, err := env.inConn.proxyToShard(env.holders[0], replicaEpoch, sweepDeadlineWriteBlob(t, env), mkem.NewScheme(s), s, time.Now().Add(5*time.Second), 1)
	require.Error(t, err)
	require.Nil(t, key)

	s.requireAllWiped(t, "proxyToShard")
}
