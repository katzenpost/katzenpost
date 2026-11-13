// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem/pem"
)

// A gateway config written for the old bolt spool, such as the ones kno
// generates, must still load: the spool is in memory and SpoolDB is ignored.
func TestGatewayLegacySpoolDBStillLoads(t *testing.T) {
	linkPubKey, _, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)
	base := `[SphinxGeometry]
  PacketLength = 3082
  NrHops = 5
  HeaderLength = 476
  RoutingInfoLength = 410
  PerHopRoutingInfoLength = 82
  SURBLength = 572
  SphinxPlaintextHeaderLength = 2
  PayloadTagLength = 32
  ForwardPayloadLength = 2574
  UserForwardPayloadLength = 2000
  SURBIDLength = 16
  RecipientIDLength = 32
  NodeIDLength = 32
  NextNodeHopLength = 65
  SPRPKeyMaterialLength = 64
  NIKEName = "x25519"
  KEMName = ""

[Server]
  WireKEM = "%s"
  PKISignatureScheme = "Ed25519"
  Identifier = "gateway.example.com"
  Addresses = [ "tcp://127.0.0.1:29483" ]
  DataDir = '%s'
  IsGatewayNode = true

[Logging]
  Level = "DEBUG"

[PKI]
  [PKI.Voting]
    [[PKI.Voting.Authorities]]
      WireKEMScheme = "%s"
      PKISignatureScheme = "Ed25519"
      Identifier = "auth1"
      IdentityPublicKey = "-----BEGIN ED25519 PUBLIC KEY-----\nxwPliuI1LbUbWbkDYQsL8gwYfYzsaxhdcY4kwp+f2W8=\n-----END ED25519 PUBLIC KEY-----\n"
      LinkPublicKey = "%s"
      Addresses = ["tcp://127.0.0.1:30001"]
`
	dir := t.TempDir()
	cfgText := fmt.Sprintf(base, testingSchemeName, dir, testingSchemeName,
		strings.ReplaceAll(pem.ToPublicPEMString(linkPubKey), "\n", "\\n"))

	t.Run("explicit limits", func(t *testing.T) {
		cfg, err := Load([]byte(cfgText + "\n[Gateway]\n  SpoolMaxRecipientBytes = 1000\n  SpoolMaxBytes = 5000\n"))
		require.NoError(t, err)
		require.Equal(t, 1000, cfg.Gateway.SpoolMaxRecipientBytes)
		require.Equal(t, 5000, cfg.Gateway.SpoolMaxBytes)
	})
	t.Run("negative limit", func(t *testing.T) {
		_, err := Load([]byte(cfgText + "\n[Gateway]\n  SpoolMaxBytes = -1\n"))
		require.ErrorContains(t, err, "must not be negative")
	})

	for _, tc := range []struct{ name, extra string }{
		{"no gateway table", ""},
		{"bolt backend", "\n[Gateway]\n  [Gateway.SpoolDB]\n    Backend = \"bolt\"\n    [Gateway.SpoolDB.Bolt]\n      SpoolDB = '" + filepath.Join(dir, "spool.db") + "'\n"},
		{"relative bolt path", "\n[Gateway]\n  [Gateway.SpoolDB]\n    Backend = \"bolt\"\n    [Gateway.SpoolDB.Bolt]\n      SpoolDB = \"spool.db\"\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load([]byte(cfgText + tc.extra))
			require.NoError(t, err)
			require.NotNil(t, cfg.Gateway)
			require.Equal(t, tc.extra == "", cfg.Gateway.SpoolDB == nil, "SpoolDB is set only when the operator wrote it")
			require.Equal(t, DefaultSpoolMaxRecipientBytes, cfg.Gateway.SpoolMaxRecipientBytes)
			require.Equal(t, DefaultSpoolMaxBytes, cfg.Gateway.SpoolMaxBytes)
		})
	}
}
