// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"testing"

	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/stretchr/testify/require"
)

func TestValidateAuthoritiesMatchesOwnLinkKey(t *testing.T) {
	ks := kemschemes.ByName("x25519")
	own, _, err := ks.GenerateKeyPair()
	require.NoError(t, err)
	other, _, err := ks.GenerateKeyPair()
	require.NoError(t, err)
	cfg := &Config{Authorities: []*Authority{{LinkPublicKey: LinkPublicKey{PublicKey: own}}, {LinkPublicKey: LinkPublicKey{}}}}
	require.NotPanics(t, func() {
		require.NoError(t, cfg.ValidateAuthorities(own))
		require.Error(t, cfg.ValidateAuthorities(other))
	})
	require.Error(t, (&Config{}).ValidateAuthorities(own))
}
