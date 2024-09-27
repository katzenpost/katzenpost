// config_test.go - Server configuration tests.
// Copyright (C) 2017  Yawning Angel
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"
)

var testingSchemeName = "x25519"
var testingScheme = schemes.ByName(testingSchemeName)

func TestConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		return
	}

	require := require.New(t)

	_, err := Load(nil)
	require.Error(err, "no Load() with nil config")
	require.EqualError(err, "No nil buffer as config file")
	linkPubKey, _, err := testingScheme.GenerateKeyPair()
	require.NoError(err)

	basicConfig := `# A basic configuration example.
[SphinxGeometry]
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

[Management]
  Enable = true
  Path = ""

[server]
  WireKEM = "%s"
  PKISignatureScheme = "Ed25519"
  Identifier = "katzenpost.example.com"
  Addresses = [ "tcp4://127.0.0.1:29483", "tcp6://[::1]:29483" ]
  DataDir = "%s"
  IsProvider = true
  MetricsAddress = "127.0.0.1:6543"

[Provider]
  [[Provider.Kaetzchen]]
    Capability = "echo"
    Endpoint = "+echo"
  [[Provider.Kaetzchen]]
    Capability = "meow"
	Endpoint = "+meow"
	Config = { Locale = "ja_JP", Meow = "Nyan", NumMeows = 3 }

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
      Addresses = ["127.0.0.1:30001"]
`

	tempDir, err := os.MkdirTemp("", "server_config_test")
	require.NoError(err)
	config := fmt.Sprintf(basicConfig, testingSchemeName, tempDir, testingSchemeName, strings.Replace(pem.ToPublicPEMString(linkPubKey), "\n", "\\n", -1))

	cfg, err := Load([]byte(config))
	require.NoError(err)

	require.True(cfg.Management.Enable)
	if cfg.Management.Path == "" {
		panic("cfg.Management.Path is empty string")
	}

	_, err = json.Marshal(cfg)
	require.NoError(err)
}

func TestIncompleteConfig(t *testing.T) {
	require := require.New(t)

	const incompletePKIConfig = `# A basic configuration example.
[SphinxGeometry]
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

[server]
Identifier = "katzenpost.example.com"
Addresses = [ "quic://127.0.0.1:29483", "tcp://[::1]:29483" ]
DataDir = "/var/lib/katzenpost"
IsProvider = true

[Provider]
  [[Provider.Kaetzchen]]
    Capability = "echo"
    Endpoint = "+echo"
  [[Provider.Kaetzchen]]
    Capability = "meow"
	Endpoint = "+meow"
	Config = { Locale = "ja_JP", Meow = "Nyan", NumMeows = 3 }

[Logging]
Level = "DEBUG"
`

	_, err := Load([]byte(incompletePKIConfig))
	require.Error(err, "Load() with incomplete config")
	require.EqualError(err, "config: No PKI block was present")

	const incompleteServerConfig = `# A basic configuration example.
[SphinxGeometry]
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

[server]
Identifier = ""
Addresses = [ "tcp://127.0.0.1:29483", "quic://[::1]:29483" ]
DataDir = "/var/lib/katzenpost"
IsProvider = true

[Provider]
  [[Provider.Kaetzchen]]
    Capability = "echo"
    Endpoint = "+echo"
  [[Provider.Kaetzchen]]
    Capability = "meow"
	Endpoint = "+meow"
	Config = { Locale = "ja_JP", Meow = "Nyan", NumMeows = 3 }

[Logging]
Level = "DEBUG"

[PKI]
[PKI.Nonvoting]
Address = "tcp://127.0.0.1:6999"
PublicKeyPem = "auth_id_pub_key.pem"
`

	_, err = Load([]byte(incompleteServerConfig))
	require.Error(err, "Load() with incomplete config")
	require.EqualError(err, "config: Server: Identifier is not set")

}
