// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/quic/common"
)

func TestReplicaPregeneratesItsQUICKeysWithoutAuthorityPins(t *testing.T) {
	logBackend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	schemes := NewTestSchemes()
	geometry := CreateTestGeometryCustom(schemes, 1234, 5)
	cfg := CreateTestConfig(t, schemes, geometry, CreateTestTempDir(t, "replica_quic_pregen_test"), "replica1", []string{"quic://127.0.0.1:1"})
	quicKeyDir := t.TempDir()
	quicKeys, err := common.NewEpochKeys(quicKeyDir, common.CurrentEpoch, nil)
	require.NoError(t, err)
	s := &Server{cfg: cfg, logBackend: logBackend, log: logBackend.GetLogger("replica"), quicKeys: quicKeys}
	p := &PKIWorker{server: s}

	hashes, err := p.quicKeyHash(common.CurrentEpoch() + 1)
	require.NoError(t, err)
	require.Nil(t, hashes)
	seeds, err := filepath.Glob(filepath.Join(quicKeyDir, "quic-tls-*.key"))
	require.NoError(t, err)
	require.Len(t, seeds, 3, "the keys for the coming epochs were not generated ahead of the handshakes that need them")
}
