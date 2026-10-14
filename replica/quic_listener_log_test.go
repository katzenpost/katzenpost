// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"os"
	"path/filepath"
	"testing"

	signschemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/replica/config"
)

func TestQUICListenerStartIsLogged(t *testing.T) {
	_, identityPrivateKey, err := signschemes.ByName(testPKIScheme).GenerateKey()
	require.NoError(t, err)
	logFile := filepath.Join(t.TempDir(), "replica.log")
	backend, err := log.New(logFile, "NOTICE", false)
	require.NoError(t, err)
	defer backend.Close()
	server := &Server{cfg: &config.Config{}, logBackend: backend, identityPrivateKey: identityPrivateKey}
	l, err := newListener(server, 0, "quic://127.0.0.1:0")
	require.NoError(t, err)
	l.Halt()
	logged, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.Contains(t, string(logged), `Starting listener on: "quic://127.0.0.1:0"`)
}
