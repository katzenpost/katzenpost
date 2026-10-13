// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQUICOptionsAreValidated(t *testing.T) {
	base := minimalCourierTOML
	_, err := Load([]byte(base + "\n[QUIC]\nAddressValidation = \"sometimes\"\n"))
	require.ErrorContains(t, err, "QUIC")
}
