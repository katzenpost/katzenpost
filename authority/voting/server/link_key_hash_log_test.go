// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
)

func TestStartupLogsLinkKeyHashAsPeersDo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("DataDir's 0700 permission check cannot pass on windows")
	}
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	scheme := kemschemes.ByName("x25519")
	pub, priv, err := scheme.GenerateKeyPair()
	require.NoError(t, err)
	require.NoError(t, kempem.PrivateKeyToFile(filepath.Join(dir, "link.private.pem"), priv))
	require.NoError(t, kempem.PublicKeyToFile(filepath.Join(dir, "link.public.pem"), pub))
	logFile := filepath.Join(dir, "authority.log")
	zero := 0
	cfg := &config.Config{
		Server: &config.Server{
			Identifier:         "auth1",
			WireKEMScheme:      "x25519",
			PKISignatureScheme: testSchemeName,
			DataDir:            dir,
		},
		Authorities: []*config.Authority{{Identifier: "auth1", LinkPublicKey: config.LinkPublicKey{PublicKey: pub}}},
		Logging:     &config.Logging{File: logFile, Level: "NOTICE"},
		Debug:       &config.Debug{GenerateOnly: true, MaxPeerConns: &zero, MaxLoopbackConns: &zero},
	}
	_, err = New(cfg)
	require.ErrorIs(t, err, ErrGenerateOnly)
	blob, err := pub.MarshalBinary()
	require.NoError(t, err)
	logged, err := os.ReadFile(logFile)
	require.NoError(t, err)
	want := hash.Sum256(blob)
	require.Contains(t, string(logged), fmt.Sprintf("Authority link public key hash is: %x", want[:]))
	require.NotContains(t, string(logged), fmt.Sprintf("%x", sha256.Sum256(blob)))
}
