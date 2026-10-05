// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	pemkem "github.com/katzenpost/hpqc/kem/pem"
	nike "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	aconfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/config"
)

func linkKeyHalfConfig(t *testing.T, dir string) *config.Config {
	scheme := signSchemes.ByName("Ed25519 Sphincs+")
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
		Logging: &config.Logging{File: filepath.Join(dir, "server.log"), Level: "ERROR"},
		PKI: &config.PKI{Voting: &config.Voting{Authorities: []*aconfig.Authority{{
			WireKEMScheme: testingSchemeName, PKISignatureScheme: scheme.Name(), Identifier: "auth1",
			IdentityPublicKey: authPub, LinkPublicKey: aconfig.LinkPublicKey{PublicKey: authLink},
			Addresses: []string{"tcp://127.0.0.1:1234"},
		}}}},
		Debug: &config.Debug{NumSphinxWorkers: 1, NumKaetzchenWorkers: 1, DisableRateLimit: true, GenerateOnly: true},
	}
	require.NoError(t, cfg.FixupAndValidate())
	return cfg
}

func TestServerLinkKeyHalfHelper(t *testing.T) {
	c := os.Getenv("KP_LINK_KEY_HALF")
	if c == "" {
		t.Skip()
	}
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	privFile := filepath.Join(dir, "link.private.pem")
	pubFile := filepath.Join(dir, "link.public.pem")
	pub, priv, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)
	if c == "both" || c == "private" {
		require.NoError(t, pemkem.PrivateKeyToFile(privFile, priv))
	}
	if c == "both" || c == "public" {
		require.NoError(t, pemkem.PublicKeyToFile(pubFile, pub))
	}
	before := map[string][]byte{}
	for _, f := range []string{privFile, pubFile} {
		if b, err := os.ReadFile(f); err == nil {
			before[f] = b
		}
	}

	_, err = New(linkKeyHalfConfig(t, dir))

	switch c {
	case "both", "none":
		require.ErrorIs(t, err, ErrGenerateOnly)
		got, err := pemkem.FromPublicPEMFile(pubFile, testingScheme)
		require.NoError(t, err)
		_, err = pemkem.FromPrivatePEMFile(privFile, testingScheme)
		require.NoError(t, err)
		if c == "both" {
			require.True(t, pub.Equal(got))
		}
	default:
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrGenerateOnly)
		require.ErrorContains(t, err, privFile)
		require.ErrorContains(t, err, pubFile)
		require.Len(t, before, 1)
		for _, f := range []string{privFile, pubFile} {
			if _, ok := before[f]; !ok {
				require.NoFileExists(t, f)
			}
		}
	}
	for f, b := range before {
		after, err := os.ReadFile(f)
		require.NoError(t, err)
		require.Equal(t, b, after)
	}
}

func runLinkKeyHalfHelper(t *testing.T, c string) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestServerLinkKeyHalfHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), "KP_LINK_KEY_HALF="+c)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}

func TestServerLinkKeyHalf(t *testing.T) {
	for _, c := range []string{"public", "private", "both", "none"} {
		t.Run(c, func(t *testing.T) {
			runLinkKeyHalfHelper(t, c)
		})
	}
}
