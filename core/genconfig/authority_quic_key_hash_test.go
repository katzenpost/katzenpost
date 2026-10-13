// SPDX-License-Identifier: AGPL-3.0-only

package genconfig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	vConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
)

func authorityQUICKeyFileHash(t *testing.T, path string) []byte {
	t.Helper()
	seed, err := os.ReadFile(path)
	require.NoError(t, err, "genconfig wrote no QUIC key for the authority")
	require.Len(t, seed, ed25519.SeedSize)
	spki, err := x509.MarshalPKIXPublicKey(ed25519.NewKeyFromSeed(seed).Public())
	require.NoError(t, err)
	h := sha256.Sum256(spki)
	return h[:]
}

func everyAuthorityEntry(s *Katzenpost) []*vConfig.Authority {
	var entries []*vConfig.Authority
	for _, a := range s.VotingAuthConfigs {
		entries = append(entries, a.Authorities...)
	}
	for _, n := range s.NodeConfigs {
		entries = append(entries, n.PKI.Voting.Authorities...)
	}
	return entries
}

func TestGenConfigPinsEveryAuthorityQUICKeyOnAQUICNetwork(t *testing.T) {
	for transport, pinned := range map[string]bool{"tcp": false, "quic": true, "alternate": true} {
		s := transportFixture(t, transport)
		entries := everyAuthorityEntry(s)
		require.NotEmpty(t, entries)
		for _, a := range entries {
			if !pinned {
				require.Empty(t, a.QUICKeyHash, "transport %s: %s has a QUICKeyHash", transport, a.Identifier)
				continue
			}
			require.Equal(t, authorityQUICKeyFileHash(t, filepath.Join(s.OutDir, a.Identifier, "quic-tls.key")), []byte(a.QUICKeyHash), "transport %s: %s is not pinned to its QUIC key", transport, a.Identifier)
		}
	}
}

func TestGenConfigLeavesAnOldAuthorityUnpinnedWithTCP(t *testing.T) {
	s := testKatzenpost(t)
	s.PkiSignatureScheme = signSchemes.ByName(testSchemeName)
	s.BaseDir = t.TempDir()
	s.LastPort = 30000
	s.Transport = "quic"
	s.NodeVersions = map[string]string{"auth2": "v0.0.104"}
	require.NoError(t, s.GenVotingAuthoritiesCfg(2, &vConfig.Parameters{Mu: 0.005, LambdaP: 0.001}, 5, s.WireKEMScheme))
	for _, a := range s.VotingAuthConfigs[0].Authorities {
		if a.Identifier == "auth2" {
			require.Empty(t, a.QUICKeyHash, "an old authority was pinned to a QUIC key it never had")
			require.Equal(t, "quic+tcp", addressSchemes(t, a.Addresses), "an old authority is left without tcp")
			continue
		}
		require.NotEmpty(t, a.QUICKeyHash, "a current authority beside an old one has no QUICKeyHash")
		require.Equal(t, "quic", addressSchemes(t, a.Addresses))
	}
}
