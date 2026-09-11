// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/log"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

type keygenRecordingScheme struct {
	nike.Scheme
	mu        sync.Mutex
	generated []nike.PrivateKey
}

func (s *keygenRecordingScheme) GenerateKeyPair() (nike.PublicKey, nike.PrivateKey, error) {
	pub, priv, err := s.Scheme.GenerateKeyPair()
	s.mu.Lock()
	s.generated = append(s.generated, priv)
	s.mu.Unlock()
	return pub, priv, err
}

func newTestEnvelopeKeys(t *testing.T, scheme nike.Scheme) *EnvelopeKeys {
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	return &EnvelopeKeys{
		log:      logBackend.GetLogger("envelope keys"),
		datadir:  t.TempDir(),
		scheme:   scheme,
		keysLock: new(sync.RWMutex),
		keys:     make(map[uint64]*replicaCommon.EnvelopeKey),
	}
}

func requirePrivateKeyWiped(t *testing.T, k nike.PrivateKey, msg string) {
	t.Helper()
	b := k.Bytes()
	require.Equal(t, make([]byte, len(b)), b, msg)
}

func TestPruneWipesExpiredEnvelopeKey(t *testing.T) {
	keys := newTestEnvelopeKeys(t, nikeschemes.ByName("X25519"))
	epoch, _, _ := replicaCommon.ReplicaNow()
	require.NoError(t, keys.Generate(epoch-20))
	expired, err := keys.GetKeypair(epoch - 20)
	require.NoError(t, err)

	require.True(t, keys.Prune())

	requirePrivateKeyWiped(t, expired.PrivateKey, "expired envelope private key left in memory after Prune")
}

func TestGenerateLeavesNoUnusedEnvelopeKey(t *testing.T) {
	scheme := &keygenRecordingScheme{Scheme: nikeschemes.ByName("X25519")}
	keys := newTestEnvelopeKeys(t, scheme)
	epoch, _, _ := replicaCommon.ReplicaNow()
	require.NoError(t, keys.Generate(epoch))
	kept, err := keys.GetKeypair(epoch)
	require.NoError(t, err)

	scheme.mu.Lock()
	defer scheme.mu.Unlock()
	for _, k := range scheme.generated {
		if k == kept.PrivateKey {
			continue
		}
		requirePrivateKeyWiped(t, k, "Generate left an unused envelope private key in memory")
	}
}
func TestGenerateWipesKeyWhenWriteFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	scheme := &keygenRecordingScheme{Scheme: nikeschemes.ByName("X25519")}
	keys := newTestEnvelopeKeys(t, scheme)
	require.NoError(t, os.Chmod(keys.datadir, 0500))
	t.Cleanup(func() { os.Chmod(keys.datadir, 0700) })
	epoch, _, _ := replicaCommon.ReplicaNow()

	require.Error(t, keys.Generate(epoch))

	scheme.mu.Lock()
	defer scheme.mu.Unlock()
	require.NotEmpty(t, scheme.generated)
	for _, k := range scheme.generated {
		requirePrivateKeyWiped(t, k, "Generate left the key it failed to write in memory")
	}
}
