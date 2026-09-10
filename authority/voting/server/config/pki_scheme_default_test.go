// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"testing"

	"github.com/stretchr/testify/require"

	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
)

// TestServerPKISignatureSchemeDefault checks an unset PKI signature scheme
// defaults to the sane, registered default (Ed25519 Sphincs+), rather than
// being a required field.
func TestServerPKISignatureSchemeDefault(t *testing.T) {
	s := &Server{}
	s.applyPKISignatureSchemeDefault()
	require.Equal(t, DefaultPKISignatureScheme, s.PKISignatureScheme)
	require.NotNil(t, signSchemes.ByName(s.PKISignatureScheme), "the default scheme must be registered")
}

// TestServerPKISignatureSchemeNotOverwritten checks an explicit scheme is kept.
func TestServerPKISignatureSchemeNotOverwritten(t *testing.T) {
	s := &Server{PKISignatureScheme: "ML-DSA-65"}
	s.applyPKISignatureSchemeDefault()
	require.Equal(t, "ML-DSA-65", s.PKISignatureScheme)
}
