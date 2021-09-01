// config_test.go - Voting authority configuration file parser tests.
// Copyright (C) 2021  Masala
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
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
)

func TestParseVotingConfig(t *testing.T) {
	require := require.New(t)
	fn, err := filepath.Abs("../../../cmd/voting/authority.toml.sample")
	require.NoError(err)

	// get the configuration object and verify that the sample
	// configuration file is valid
	cfg, err := LoadFile(fn, false)
	require.NoError(err)
	require.NotNil(cfg)
	require.Equal(3, len(cfg.Topology.Layers))
	for _, l := range cfg.Topology.Layers {
		require.Equal(1, len(l.Nodes))
	}
}
