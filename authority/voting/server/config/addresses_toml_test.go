// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"testing"

	"github.com/stretchr/testify/require"

	kempem "github.com/katzenpost/hpqc/kem/pem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"
)

// Authority.UnmarshalTOML parses the Addresses field with type assertions on
// pos.([]interface{}) and addr.(string). This test drives an Addresses value
// that is a scalar and one that contains a non-string element through
// UnmarshalTOML and expects a returned error rather than a panic.
func TestUnmarshalTOMLRejectsMalformedAddresses(t *testing.T) {
	ss := signschemes.ByName("ed25519")
	require.NotNil(t, ss)
	ks := kemschemes.ByName("Xwing")
	require.NotNil(t, ks)
	idPub, _, err := ss.GenerateKey()
	require.NoError(t, err)
	linkPub, _, err := ks.GenerateKeyPair()
	require.NoError(t, err)

	base := func() map[string]interface{} {
		return map[string]interface{}{
			"Identifier":         "auth1",
			"PKISignatureScheme": ss.Name(),
			"IdentityPublicKey":  signpem.ToPublicPEMString(idPub),
			"WireKEMScheme":      ks.Name(),
			"LinkPublicKey":      kempem.ToPublicPEMString(linkPub),
		}
	}

	// Addresses as a scalar string instead of an array.
	scalar := base()
	scalar["Addresses"] = "tcp://127.0.0.1:1234"
	// Addresses as an array with a non-string element.
	badElem := base()
	badElem["Addresses"] = []interface{}{int64(123)}

	cases := map[string]map[string]interface{}{
		"scalar":             scalar,
		"non-string-element": badElem,
	}
	for name, data := range cases {
		data := data
		t.Run(name, func(t *testing.T) {
			var a Authority
			var gotErr error
			require.NotPanics(t, func() {
				gotErr = a.UnmarshalTOML(data)
			}, "UnmarshalTOML must return an error, not panic, on a malformed Addresses field")
			require.Error(t, gotErr, "UnmarshalTOML must reject a malformed Addresses field")
		})
	}
}
