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

func TestIdentifierNormalizedValues(t *testing.T) {
	for id, want := range map[string]string{
		"Replica1":              "replica1",
		"Storage.Example.ORG":   "storage.example.org",
		"B\u00fccher.Example":   "xn--bcher-kva.example",
		"xn--bcher-kva.example": "xn--bcher-kva.example",
	} {
		c, err := loadWithIdentifier(t, id)
		require.NoError(t, err, id)
		require.Equal(t, want, c.Identifier, id)
	}
}

func TestIdentifierRejectionNamesTheField(t *testing.T) {
	_, err := loadWithIdentifier(t, "xn--zz")
	require.ErrorContains(t, err, "Identifier")

	_, err = loadWithIdentifier(t, "")
	require.ErrorContains(t, err, "Identifier is not set")
}
