package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	cfg, err := LoadFile("../testdata/client.toml")
	require.NoError(t, err)

	t.Logf("cfg %v", cfg)
}
