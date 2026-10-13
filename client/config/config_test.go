package config

import (
	"bytes"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	cfg, err := LoadFile(TestClientTOML)
	require.NoError(t, err)

	t.Logf("cfg %v", cfg)
}

func TestEncodedConfigCarriesDBusNameOnlyWhenSet(t *testing.T) {
	for _, name := range []string{"", "network.katzenpost.kpclientd"} {
		var b bytes.Buffer
		require.NoError(t, toml.NewEncoder(&b).Encode(&Config{DBusName: name}))
		md, err := toml.Decode(b.String(), new(Config))
		require.NoError(t, err)
		require.Equal(t, name != "", md.IsDefined("DBusName"), b.String())
	}
}
