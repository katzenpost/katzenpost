// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/wire"
)

// TestAuthorityAuthenticatorShortADDoesNotPanic is the regression for the
// unchecked AdditionalData slice on the client's authenticator: a responder
// that presents an AD shorter than the identity-hash size must be rejected,
// not crash the fetching client mid-handshake.
func TestAuthorityAuthenticatorShortADDoesNotPanic(t *testing.T) {
	lb, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	scheme := signschemes.ByName("Ed25519 Sphincs+")
	require.NotNil(t, scheme)
	pub, _, err := scheme.GenerateKey()
	require.NoError(t, err)

	a := &authorityAuthenticator{IdentityPublicKey: pub, log: lb.GetLogger("ad-test")}
	for _, n := range []int{0, 1, hash.HashSize - 1} {
		require.NotPanics(t, func() {
			require.False(t, a.IsPeerValid(&wire.PeerCredentials{AdditionalData: make([]byte, n)}))
		}, "IsPeerValid panicked on a %d-byte AD", n)
	}
}
