// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	pemkem "github.com/katzenpost/hpqc/kem/pem"
	nike "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	aconfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/config"
)

func TestServerLinkKeyHelper(t *testing.T) {
	dir := os.Getenv("KP_LINK_KEY_DIR")
	if dir == "" {
		t.Skip()
	}
	scheme := signSchemes.ByName(testSchemeName)
	authPub, _, err := scheme.GenerateKey()
	require.NoError(t, err)
	authLink, _, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)
	cfg := &config.Config{
		Management:     &config.Management{},
		SphinxGeometry: geo.GeometryFromUserForwardPayloadLength(nike.Scheme(rand.Reader), 2000, true, 5),
		Server: &config.Server{
			WireKEM:            testingSchemeName,
			PKISignatureScheme: scheme.Name(),
			Identifier:         "mix1",
			Addresses:          []string{"tcp://127.0.0.1:0"},
			DataDir:            dir,
		},
		Logging: &config.Logging{File: filepath.Join(dir, "server.log"), Level: "NOTICE"},
		PKI: &config.PKI{Voting: &config.Voting{Authorities: []*aconfig.Authority{{
			WireKEMScheme: testingSchemeName, PKISignatureScheme: scheme.Name(), Identifier: "auth1",
			IdentityPublicKey: authPub, LinkPublicKey: aconfig.LinkPublicKey{PublicKey: authLink},
			Addresses: []string{"tcp://127.0.0.1:1234"},
		}}}},
		Debug: &config.Debug{NumSphinxWorkers: 1, NumKaetzchenWorkers: 1, DisableRateLimit: true, GenerateOnly: true},
	}
	require.NoError(t, cfg.FixupAndValidate())
	_, err = New(cfg)
	require.ErrorIs(t, err, ErrGenerateOnly)
}

func runLinkKeyHelper(t *testing.T, dir string) string {
	cmd := exec.Command(os.Args[0], "-test.run=^TestServerLinkKeyHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), "KP_LINK_KEY_DIR="+dir)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	logged, err := os.ReadFile(filepath.Join(dir, "server.log"))
	require.NoError(t, err)
	require.NoError(t, os.Remove(filepath.Join(dir, "server.log")))
	return string(logged)
}

func diskLinkKeyLine(t *testing.T, dir string) string {
	pub, err := pemkem.FromPublicPEMFile(filepath.Join(dir, "link.public.pem"), testingScheme)
	require.NoError(t, err)
	blob, err := pub.MarshalBinary()
	require.NoError(t, err)
	h := hash.Sum256(blob)
	return fmt.Sprintf("Server link public key hash is: %x", h[:])
}

func TestServerUsesTheLinkKeyItWrites(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("DataDir's 0700 permission check cannot pass on windows")
	}
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	first := runLinkKeyHelper(t, dir)
	want := diskLinkKeyLine(t, dir)
	require.Contains(t, first, want)
	require.Contains(t, runLinkKeyHelper(t, dir), want)
}
