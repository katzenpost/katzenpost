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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	require := require.New(t)

	_, err := Load(nil)
	require.Error(err, "no Load() with nil config")
	require.EqualError(err, "No nil buffer as config file")

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

[server]
Identifier = "katzenpost.example.com"
Addresses = [ "127.0.0.1:29483", "[::1]:29483" ]
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
      Identifier = "auth1"
      IdentityPublicKey = "-----BEGIN ED25519 SPHINCS+ PUBLIC KEY-----\n/39gYfCseEPDx8HOjYGpf1SKNWRugqewE7IN3OF5F+fUf3J3kNECeSFowy5m2CAE\n+bwvfBS+r1LhiqOaV4ZSk1b7gwdCBaFdjnKCYscBYQMuJ4H72bfQPinsc6w5VLZb\n-----END ED25519 SPHINCS+ PUBLIC KEY-----\n"
      LinkPublicKey = "-----BEGIN KYBER768-X25519 PUBLIC KEY-----\nK1kxEr5MfkDhs4eAQ0dphQPnDwX7QT2rdilOFLHqgS0RCG0aCkQFW1NLNh7Zew0E\neoiONZpBLL+DqqQp4ZZkcjSB5FOoVTHyVmbrWYobc6nJkMkr9YKG1z3k8iKqpWkh\ngaIMzFpemHbw1UJ9FL4wum4EDBnExTI0tLOJOUuOybijeyxhF0RjpmsbQoWECkGC\nKmjR9AX8REIO4AXGSLJVlXQ8yQQJqZD5RS2WKz59SFiD0Rq9Bg9IBheQFW8/SGcI\n2Z9s4kNYGlOCrKgmqk/wws+9qqiq00iCV3/o01fOWH6asUnI5lMrhTB4lkUuUDXP\nLBhMC8TBxsO8RZb5k8OMN83PFbEJWK1sxY8jsrWF+cggSwJLBgQkFy2p4ae6tGI8\nkrzSR4+7hSfPFJ4bgJeZ3Gvt+ozhlJJ3qRrzkIarCKBBxGUKoYcIcCTGAi0ylnFx\n+DU8l2vTqGqUN2VOqca2KxF/+QMTxX40QyIU8zv3s8S1iBWY80ScwDz6nHWqM3Kg\nyJ5QwRYoQ5v6oUA5nGiPe87SgzVQJ1iWQlaHrA7cmyTSDDaWTKpaloUEFkyk8CO1\nM1AD+of85BOMAjgld7sEggHEw7OBnAephy/l2mis8VVLIY5/iMgVlYXqcQFvlYvl\ngnd5vGHYsjyaYDyEhYyCOJckMVUeVCp9AnNdcXu8giqLpig5ukjJqKRsZRsldU09\nYlbDLD4KkyaRJqZeRx2HSww9xRHlaiWpNiAou8YWpY/lpxeVYpIwmLThhSetsGnU\nAbISWWTdo5+DuzvXrAf64lQoR2qRWnS0HAYWFLtQqwMnZ68GBgIQt0LS8087Bj8F\nxDcEFKl9YsIdJ3GAqHJl0Up1DE+dLGAKuFANFl62OL6NUzunMV0/a3e8fLIBljST\n/HWDwhWX2HsQRFZ62hM2qz21wmNDCzdk4BHImixGU3SNG5MoBBfKcqJ1RpYfQT/A\naHZtQwlnKzhcs0VMSWZnF53pAZyF968JaCzA6J0d4JWAIi83OHVinAoj4Vyz2YeK\ngHo/bHVTUzz3N63exc8t0X8GIQ0WuFmLwZq3ZmLLowxJyVCSxQx4Oo7qBGkgV4O9\nJsgFMX7et4ZRfJF9C8C0A6+5ZBKTXKuxkYhfpwyKtUYbjIviglvm0n+AaCXyfJRH\n+3tSOWZWxQxtmgh9GIqkaJt9AQ/W+SG+fJowN2A8cyrAHH9bSGJlkmiJkqrJ2ZQ7\no6VoZVfNpsWG5lUcgJI0UIMQcTmdCCQkzCWK8MN+Y65d9Ed/i5PgADu0NKKuBnG3\nujKS6mx6+CpgpkAjh6GlBcZIgjry4cYfNgcM9wNIdichWLFQ9WZJcJpR/AL7hEoD\n9rmJKxMsdwvjhVNyejAp4woJMz/AaXIlhVMQAAIjCr4UR3KerItY0QUPVz+qd8Qo\nMzBJcFu51cOSZ73sWjzNc4TttA3BAV2dRJH8y0dIUFtx92ynVyFe2W+EUswucC7U\n3D+xojMBs8Gm8YX8OEVC95DjYzqS+L+RdcMcaLU4pDzUyEMaW2dLY7aUix4N8aZT\nlAq/Yz5lGmoaFSVHuGmp6zMnsbb+shToRROp5pTU66ab8yDrY6y1UtrOTbtPRGWi\nz59pLFWh/FAHHk73yORNTg==\n-----END KYBER768-X25519 PUBLIC KEY-----\n"
      Addresses = ["127.0.0.1:30001"]
`

	config := fmt.Sprintf(basicConfig, os.TempDir())

	cfg, err := Load([]byte(config))
	require.NoError(err, "Load() with basic config")

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
Addresses = [ "127.0.0.1:29483", "[::1]:29483" ]
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
Addresses = [ "127.0.0.1:29483", "[::1]:29483" ]
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
Address = "127.0.0.1:6999"
PublicKeyPem = "auth_id_pub_key.pem"
`

	_, err = Load([]byte(incompleteServerConfig))
	require.Error(err, "Load() with incomplete config")
	require.EqualError(err, "config: Server: Identifier is not set")

}
