// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/idna"
)

func loadWithIdentifier(t *testing.T, id string) (*Config, error) {
	b, err := os.ReadFile("testdata/replica.toml")
	require.NoError(t, err)
	s := strings.Replace(string(b), `Identifier = "replica1"`, `Identifier = "`+id+`"`, 1)
	return Load([]byte(s), false)
}

func TestIdentifierNormalizedLikeTheAuthority(t *testing.T) {
	for _, id := range []string{"Replica1", "REPLICA1", "replica1", "Storage.Example.ORG"} {
		c, err := loadWithIdentifier(t, id)
		require.NoError(t, err, id)
		want, err := idna.Lookup.ToASCII(id)
		require.NoError(t, err)
		require.Equal(t, want, c.Identifier, id)
	}
}

func TestIdentifierInvalidIsRejected(t *testing.T) {
	_, err := loadWithIdentifier(t, "xn--zz")
	require.Error(t, err)
}
