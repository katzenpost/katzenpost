// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"testing"

	"github.com/stretchr/testify/require"

	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/cert"
)

// A descriptor upload with a missing or wrong-sized signature must be rejected
// without panicking: a nil Signature would otherwise nil-deref, and a
// wrong-sized payload would panic the hybrid sign scheme's Verify.
func TestSignedUploadVerifyRejectsMalformedSignatureWithoutPanic(t *testing.T) {
	t.Parallel()
	scheme := signSchemes.ByName("Ed25519 Sphincs+")
	if scheme == nil {
		t.Skip("Ed25519 Sphincs+ is not built on this platform")
	}
	pub, _, err := scheme.GenerateKey()
	require.NoError(t, err)

	for _, sig := range []*cert.Signature{nil, {Payload: nil}, {Payload: []byte{1, 2, 3}}} {
		su := &SignedUpload{Signature: sig, MixDescriptor: &MixDescriptor{}}
		require.NotPanics(t, func() {
			require.False(t, su.Verify(pub))
		})
		ru := &SignedReplicaUpload{Signature: sig, ReplicaDescriptor: &ReplicaDescriptor{}}
		require.NotPanics(t, func() {
			require.False(t, ru.Verify(pub))
		})
	}
}
