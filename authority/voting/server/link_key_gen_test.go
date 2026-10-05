// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
)

func TestNewGeneratesAndUsesItsLinkKey(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	logFile := filepath.Join(dir, "authority.log")
	zero := 0
	cfg := &config.Config{
		Server: &config.Server{
			Identifier:         "auth1",
			WireKEMScheme:      "x25519",
			PKISignatureScheme: "Ed25519 Sphincs+",
			DataDir:            dir,
		},
		Logging: &config.Logging{File: logFile, Level: "NOTICE"},
		Debug:   &config.Debug{GenerateOnly: true, MaxPeerConns: &zero, MaxLoopbackConns: &zero},
	}
	require.NotPanics(t, func() {
		_, err := New(cfg)
		require.ErrorIs(t, err, ErrGenerateOnly)
	})
	pub, err := kempem.FromPublicPEMFile(filepath.Join(dir, "link.public.pem"), kemschemes.ByName("x25519"))
	require.NoError(t, err)
	_, err = kempem.FromPrivatePEMFile(filepath.Join(dir, "link.private.pem"), kemschemes.ByName("x25519"))
	require.NoError(t, err)
	blob, err := pub.MarshalBinary()
	require.NoError(t, err)
	logged, err := os.ReadFile(logFile)
	require.NoError(t, err)
	b2 := hash.Sum256(blob)
	s2 := sha256.Sum256(blob)
	line := string(logged)
	require.True(t, strings.Contains(line, fmt.Sprintf("Authority link public key hash is: %x", b2[:])) ||
		strings.Contains(line, fmt.Sprintf("Authority link public key hash is: %x", s2[:])), line)
}
