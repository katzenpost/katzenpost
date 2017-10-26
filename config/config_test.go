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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	require := require.New(t)

	_, err := Load(nil)
	require.Error(err, "Load() with nil config")

	const basicConfig = `# A basic configuration example.
[server]
Identifier = "katzenpost.example.com"
Addresses = [ "127.0.0.1:29483", "[::1]:29483" ]
DataDir = "/var/lib/katzenpost"
IsProvider = true

[Logging]
Level = "DEBUG"

[PKI]
[PKI.Nonvoting]
Address = "127.0.0.1:6999"
PublicKey = "kAiVchOBwHVtKJVFJLsdCQ9UyN2SlfhLHYqT8ePBetg="
`

	cfg, err := Load([]byte(basicConfig))
	require.NoError(err, "Load() with basic config")
	_ = cfg
}
