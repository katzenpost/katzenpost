// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQUICOptionsAreValidated(t *testing.T) {
	b, err := os.ReadFile(TestClientTOML)
	require.NoError(t, err)
	base := string(b)
	_, err = Load([]byte(base + "\n[QUIC]\nAddressValidation = \"sometimes\"\n"))
	require.ErrorContains(t, err, "QUIC")
}
