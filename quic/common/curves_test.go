// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCurvePreferences(t *testing.T) {
	state, err := handshakeWith(t, nil, nil)
	require.NoError(t, err)
	require.Equal(t, tls.X25519MLKEM768, state.CurveID, "the default must stay crypto/tls's")

	x25519 := &Options{CurvePreferences: []string{"X25519"}}
	state, err = handshakeWith(t, x25519, x25519)
	require.NoError(t, err)
	require.Equal(t, tls.X25519, state.CurveID)

	state, err = handshakeWith(t, nil, x25519)
	require.NoError(t, err)
	require.Equal(t, tls.X25519, state.CurveID, "a dialer limited to X25519 must still reach a default listener")
}
