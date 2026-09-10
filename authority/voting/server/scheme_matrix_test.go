// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
)

// TestVoteAllSignatureSchemes runs a full three-authority voting round with
// each registered PKI signature scheme configured as the single scheme, and
// asserts a threshold consensus forms and verifies. This is the compatibility
// guarantee that matters in practice: a deployment picks one scheme and never
// migrates, so the whole dirauth + consensus stack must work with any of them.
//
// It swaps the package-global testSignatureScheme, which every authority and
// node in the harness keys off, so the subtests must not run in parallel.
func TestVoteAllSignatureSchemes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the full signature-scheme matrix in -short mode (SPHINCS+ is slow)")
	}
	saved := testSignatureScheme
	defer func() { testSignatureScheme = saved }()

	for _, name := range signSchemes.All() {
		scheme := name
		t.Run(scheme.Name(), func(t *testing.T) {
			testSignatureScheme = scheme
			testVoteWithAuthorities(t, 3, 3)
		})
	}
}
