// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/wire"
)

// TestStateIsPeerValidShortADDoesNotPanic is the regression for the unchecked
// AdditionalData slice on the dirauth's outgoing authenticator: a peer that
// presents an AD shorter than the identity-hash size must be rejected, not
// crash the sending authority.
func TestStateIsPeerValidShortADDoesNotPanic(t *testing.T) {
	st := &state{}
	for _, n := range []int{0, 1, publicKeyHashSize - 1} {
		require.NotPanics(t, func() {
			require.False(t, st.IsPeerValid(&wire.PeerCredentials{AdditionalData: make([]byte, n)}))
		}, "IsPeerValid panicked on a %d-byte AD", n)
	}
}
