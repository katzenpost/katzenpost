// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem/pem"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
)

func serverTOML(t *testing.T, serverKeys string) string {
	linkPub, _, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)
	idPub, _, err := signSchemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	quote := func(s string) string { return strings.ReplaceAll(s, "\n", "\\n") }
	return fmt.Sprintf(`[SphinxGeometry]
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
%s  WireKEM = "%s"
  PKISignatureScheme = "%s"
  Identifier = "mix1"
  Addresses = [ "tcp4://127.0.0.1:29483" ]
  DataDir = "%s"

[Logging]
  Level = "DEBUG"

[PKI]
  [PKI.Voting]
    [[PKI.Voting.Authorities]]
      WireKEMScheme = "%s"
      PKISignatureScheme = "%s"
      Identifier = "auth1"
      IdentityPublicKey = "%s"
      LinkPublicKey = "%s"
      Addresses = ["tcp://127.0.0.1:30001"]
`, serverKeys, testingSchemeName, testSchemeName, t.TempDir(), testingSchemeName, testSchemeName,
		quote(signpem.ToPublicPEMString(idPub)), quote(pem.ToPublicPEMString(linkPub)))
}

func TestLoadIgnoresUnknownFutureKeys(t *testing.T) {
	_, err := Load([]byte("FutureKey = \"x\"\n" + serverTOML(t, "  FutureKey = 1\n") + "\n[FutureTable]\nFutureKey = 1\n"))
	require.NoError(t, err)
}
