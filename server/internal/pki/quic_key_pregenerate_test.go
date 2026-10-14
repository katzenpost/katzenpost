// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQUICNodePregeneratesItsKeysWithoutAuthorityPins(t *testing.T) {
	quicKeyDir := t.TempDir()
	desc, _, _ := publishedDescriptorLogged(t, testSchemeName, []string{"quic://127.0.0.1:4242"}, pinnedAuthorities(false), quicKeyDir, "")
	require.Nil(t, desc.QUICKeyHash)
	seeds, err := filepath.Glob(filepath.Join(quicKeyDir, "quic-tls-*.key"))
	require.NoError(t, err)
	require.Len(t, seeds, 3, "the keys for the coming epochs were not generated ahead of the handshakes that need them")
}
