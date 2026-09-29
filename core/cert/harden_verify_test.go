// SPDX-License-Identifier: AGPL-3.0-only

package cert

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
)

// A certificate carrying a wrong-sized signature payload must be rejected as a
// bad signature, not crash the process. The hybrid "Ed25519 Sphincs+" scheme's
// Verify panics on a malformed signature length in the current hpqc, so this
// exercises the guard against the real panicking dependency.
func TestVerifyRejectsWrongSizedSignatureWithoutPanic(t *testing.T) {
	t.Parallel()
	scheme := schemes.ByName("Ed25519 Sphincs+")
	if scheme == nil {
		t.Skip("Ed25519 Sphincs+ is not built on this platform")
	}
	pub, priv, err := scheme.GenerateKey()
	require.NoError(t, err)

	current, _, _ := epochtime.Now()
	raw, err := Sign(priv, pub, []byte("certified payload"), current+1)
	require.NoError(t, err)

	c := new(Certificate)
	require.NoError(t, cbor.Unmarshal(raw, c))
	for k, sig := range c.Signatures {
		sig.Payload = []byte{1, 2, 3}
		c.Signatures[k] = sig
	}
	bad, err := c.Marshal()
	require.NoError(t, err)

	require.NotPanics(t, func() {
		_, verr := Verify(pub, bad)
		require.ErrorIs(t, verr, ErrBadSignature)
	})
}
