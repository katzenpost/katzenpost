// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
)

func authorityQUICKeyHash(t *testing.T, dataDir string) []byte {
	t.Helper()
	seed, err := os.ReadFile(filepath.Join(dataDir, "quic-tls.key"))
	require.NoError(t, err, "the authority keeps no QUIC key in its DataDir")
	require.Len(t, seed, ed25519.SeedSize)
	spki, err := x509.MarshalPKIXPublicKey(ed25519.NewKeyFromSeed(seed).Public())
	require.NoError(t, err)
	h := sha256.Sum256(spki)
	return h[:]
}

func loggedQUICAuthority(t *testing.T, dataDir, logFile string) *Server {
	t.Helper()
	_, identityPrivateKey, err := signschemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	backend, err := log.New(logFile, "DEBUG", false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })
	return &Server{
		cfg:                &config.Config{Server: &config.Server{DataDir: dataDir}},
		log:                backend.GetLogger("server"),
		identityPrivateKey: identityPrivateKey,
		state:              &state{},
		haltedCh:           make(chan interface{}),
	}
}

func TestAuthorityQUICListenerPresentsItsStaticKey(t *testing.T) {
	dataDir := t.TempDir()
	logFile := filepath.Join(t.TempDir(), "authority.log")
	addr := startQUICAuthority(t, loggedQUICAuthority(t, dataDir, logFile))
	pin := authorityQUICKeyHash(t, dataDir)
	leaf, err := presentedCertificate(t, addr, pin)
	require.NoError(t, err, "the authority presented a key other than the one in its DataDir")
	now := time.Now()
	require.True(t, !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter), "validity [%v, %v] does not contain now", leaf.NotBefore, leaf.NotAfter)
	logged, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.Contains(t, string(logged), "QUIC key hash "+hex.EncodeToString(pin))

	addr = startQUICAuthority(t, loggedQUICAuthority(t, dataDir, filepath.Join(t.TempDir(), "restarted.log")))
	_, err = presentedCertificate(t, addr, pin)
	require.NoError(t, err, "a restarted authority presented a key other than the one in its DataDir")
}
