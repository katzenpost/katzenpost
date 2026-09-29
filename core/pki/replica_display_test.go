// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"testing"

	"github.com/stretchr/testify/require"

	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"
)

// TestReplicaDescriptorDisplayWithSchemesShortKeyNoPanic proves the debug
// rendering of a ReplicaDescriptor does not crash on a short/malformed key. The
// hybrid "Ed25519 Sphincs+" scheme's UnmarshalBinaryPublicKey slices without a
// length check and panics on a too-short key; DisplayWithSchemes is reachable
// unguarded from courier debug logging, so it must return a safe placeholder
// instead of panicking.
func TestReplicaDescriptorDisplayWithSchemesShortKeyNoPanic(t *testing.T) {
	idScheme := signschemes.ByName("Ed25519 Sphincs+")
	if idScheme == nil {
		t.Skip("Ed25519 Sphincs+ is not built on this platform")
	}
	linkScheme := kemschemes.ByName("Xwing")
	require.NotNil(t, linkScheme)
	envScheme := nikeschemes.ByName("x25519")
	require.NotNil(t, envScheme)

	d := &ReplicaDescriptor{
		Name:         "replica",
		IdentityKey:  []byte{1, 2, 3},
		LinkKey:      []byte{1, 2, 3},
		EnvelopeKeys: map[uint64][]byte{},
	}

	require.NotPanics(t, func() {
		out := d.DisplayWithSchemes(linkScheme, idScheme, envScheme)
		require.NotEmpty(t, out)
	}, "DisplayWithSchemes must not panic on a malformed key")
}
