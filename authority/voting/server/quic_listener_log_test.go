// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
)

func TestQUICListenerStartIsLogged(t *testing.T) {
	_, identityPrivateKey, err := signschemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	logFile := filepath.Join(t.TempDir(), "authority.log")
	backend, err := log.New(logFile, "NOTICE", false)
	require.NoError(t, err)
	defer backend.Close()
	s := &Server{
		cfg:                &config.Config{Server: &config.Server{DataDir: t.TempDir()}},
		log:                backend.GetLogger("server"),
		identityPrivateKey: identityPrivateKey,
		state:              &state{},
		haltedCh:           make(chan interface{}),
	}
	s.startListeners([]string{"quic://127.0.0.1:0"})
	require.Len(t, s.listeners, 1)
	close(s.haltedCh)
	s.listeners[0].Close()
	s.Wait()
	logged, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.Contains(t, string(logged), `Starting listener on: "quic://127.0.0.1:0"`)
}
