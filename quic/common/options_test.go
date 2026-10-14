// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOptionsValidate(t *testing.T) {
	require.NoError(t, (*Options)(nil).Validate())
	require.NoError(t, (&Options{}).Validate())
	period, jitter := 20*time.Second, 0.25
	require.NoError(t, (&Options{
		ALPN:              "h3",
		CurvePreferences:  []string{"X25519", "X25519MLKEM768"},
		AddressValidation: "under-load",
		KeepAlivePeriod:   &period,
		KeepAliveJitter:   &jitter,
	}).Validate())
	for _, mode := range []string{"always", "under-load", "off"} {
		require.NoError(t, (&Options{AddressValidation: mode}).Validate(), mode)
	}
	negative, one, below := -time.Second, 1.0, -0.1
	for name, o := range map[string]*Options{
		"alpn too long":      {ALPN: strings.Repeat("a", 256)},
		"unknown curve":      {CurvePreferences: []string{"X448"}},
		"repeated curve":     {CurvePreferences: []string{"X25519", "X25519"}},
		"unknown validation": {AddressValidation: "sometimes"},
		"negative keepalive": {KeepAlivePeriod: &negative},
		"jitter of one":      {KeepAliveJitter: &one},
		"negative jitter":    {KeepAliveJitter: &below},
	} {
		require.Error(t, o.Validate(), name)
	}
}
