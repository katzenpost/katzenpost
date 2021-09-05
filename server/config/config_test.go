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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	require := require.New(t)

	_, err := Load(nil)
	require.Error(err, "no Load() with nil config")
	require.EqualError(err, "No nil buffer as config file")

	const basicConfig = `# A basic configuration example.
[server]
Identifier = "katzenpost.example.com"
Addresses = [ "127.0.0.1:29483", "[::1]:29483" ]
DataDir = "/var/lib/katzenpost"
IsProvider = true

[Provider]
  BinaryRecipients = true
  [[Provider.Kaetzchen]]
    Capability = "loop"
    Endpoint = "+loop"
  [[Provider.Kaetzchen]]
    Capability = "meow"
	Endpoint = "+meow"
	Config = { Locale = "ja_JP", Meow = "Nyan", NumMeows = 3 }

[Logging]
Level = "DEBUG"

[PKI]
[PKI.Nonvoting]
Address = "127.0.0.1:6999"
PublicKey = "kAiVchOBwHVtKJVFJLsdCQ9UyN2SlfhLHYqT8ePBetg="
`

	cfg, err := Load([]byte(basicConfig))
	require.NoError(err, "Load() with basic config")

	jCfg, _ := json.Marshal(cfg)
	t.Logf("cfg: %v", string(jCfg))
}

func TestIncompleteConfig(t *testing.T) {
	require := require.New(t)

	const incompletePKIConfig = `# A basic configuration example.
[server]
Identifier = "katzenpost.example.com"
Addresses = [ "127.0.0.1:29483", "[::1]:29483" ]
DataDir = "/var/lib/katzenpost"
IsProvider = true

[Provider]
  BinaryRecipients = true
  [[Provider.Kaetzchen]]
    Capability = "loop"
    Endpoint = "+loop"
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
[server]
Identifier = ""
Addresses = [ "127.0.0.1:29483", "[::1]:29483" ]
DataDir = "/var/lib/katzenpost"
IsProvider = true

[Provider]
  BinaryRecipients = true
  [[Provider.Kaetzchen]]
    Capability = "loop"
    Endpoint = "+loop"
  [[Provider.Kaetzchen]]
    Capability = "meow"
	Endpoint = "+meow"
	Config = { Locale = "ja_JP", Meow = "Nyan", NumMeows = 3 }

[Logging]
Level = "DEBUG"

[PKI]
[PKI.Nonvoting]
Address = "127.0.0.1:6999"
PublicKey = "kAiVchOBwHVtKJVFJLsdCQ9UyN2SlfhLHYqT8ePBetg="
`

	_, err = Load([]byte(incompleteServerConfig))
	require.Error(err, "Load() with incomplete config")
	require.EqualError(err, "config: Server: Identifier is not set")

}
