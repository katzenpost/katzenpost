// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	nike "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	aconfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/config"
)

func ownKeyServerConfig(t *testing.T) (*config.Config, string) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	scheme := signSchemes.ByName(testSchemeName)
	authPub, _, err := scheme.GenerateKey()
	require.NoError(t, err)
	authLink, _, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)
	cfg := &config.Config{
		Management:     &config.Management{},
		SphinxGeometry: geo.GeometryFromUserForwardPayloadLength(nike.Scheme(rand.Reader), 2000, true, 5),
		Server: &config.Server{
			WireKEM:                testingSchemeName,
			PKISignatureScheme:     scheme.Name(),
			Identifier:             "mix1",
			Addresses:              []string{"tcp://127.0.0.1:0"},
			DataDir:                dir,
			IdentityPrivateKeyFile: "id.key",
			IdentityPublicKeyFile:  filepath.Join(dir, "id.pub"),
			LinkPrivateKeyFile:     "link.key",
			LinkPublicKeyFile:      filepath.Join(dir, "link.pub"),
		},
		Logging: &config.Logging{File: filepath.Join(dir, "server.log"), Level: "ERROR"},
		PKI: &config.PKI{Voting: &config.Voting{Authorities: []*aconfig.Authority{{
			WireKEMScheme: testingSchemeName, PKISignatureScheme: scheme.Name(), Identifier: "auth1",
			IdentityPublicKey: authPub, LinkPublicKey: aconfig.LinkPublicKey{PublicKey: authLink},
			Addresses: []string{"tcp://127.0.0.1:1234"},
		}}}},
		Debug: &config.Debug{NumSphinxWorkers: 1, NumKaetzchenWorkers: 1, DisableRateLimit: true, GenerateOnly: true},
	}
	require.NoError(t, cfg.FixupAndValidate())
	return cfg, dir
}

func TestServerOwnKeysHelper(t *testing.T) {
	c := os.Getenv("KP_OWN_KEY_CASE")
	if c == "" {
		t.Skip()
	}
	cfg, dir := ownKeyServerConfig(t)
	if c == "half" {
		pub, _, err := signSchemes.ByName(testSchemeName).GenerateKey()
		require.NoError(t, err)
		require.NoError(t, signpem.PublicKeyToFile(filepath.Join(dir, "id.pub"), pub))
		_, err = New(cfg)
		require.ErrorContains(t, err, filepath.Join(dir, "id.key"))
		return
	}
	_, err := New(cfg)
	require.ErrorIs(t, err, ErrGenerateOnly)
	for _, name := range []string{"id.key", "id.pub", "link.key", "link.pub"} {
		require.FileExists(t, filepath.Join(dir, name))
	}
	for _, name := range []string{"identity.private.pem", "identity.public.pem", "link.private.pem", "link.public.pem"} {
		require.NoFileExists(t, filepath.Join(dir, name))
	}
}

func runOwnKeysHelper(t *testing.T, c string) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestServerOwnKeysHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), "KP_OWN_KEY_CASE="+c)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}

func TestServerGeneratesOwnKeysAtConfiguredPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("DataDir's 0700 permission check cannot pass on windows")
	}
	runOwnKeysHelper(t, "generate")
}

func TestServerRefusesHalfAConfiguredIdentityKeyPair(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("DataDir's 0700 permission check cannot pass on windows")
	}
	runOwnKeysHelper(t, "half")
}
