// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"bytes"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"
)

func TestOwnKeyFilesOmittedWhenEmpty(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, toml.NewEncoder(&buf).Encode(&Config{Server: &Server{DataDir: "/data"}}))
	for _, k := range []string{"IdentityPrivateKeyFile", "IdentityPublicKeyFile", "LinkPrivateKeyFile", "LinkPublicKeyFile"} {
		require.NotContains(t, buf.String(), k)
	}

	buf.Reset()
	require.NoError(t, toml.NewEncoder(&buf).Encode(&Config{Server: &Server{IdentityPublicKeyFile: "/keys/id.pem"}}))
	require.Contains(t, buf.String(), `IdentityPublicKeyFile = "/keys/id.pem"`)
}
