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

// A peer block that omits PKISignatureScheme inherits DefaultPKISignatureScheme
// instead of failing, matching how the [Server] block defaults the same field.
// A present-but-unknown scheme still errors.
func TestUnmarshalTOMLPKISignatureSchemeDefault(t *testing.T) {
	ss := signschemes.ByName(DefaultPKISignatureScheme)
	require.NotNil(t, ss)
	ks := kemschemes.ByName("Xwing")
	require.NotNil(t, ks)
	idPub, _, err := ss.GenerateKey()
	require.NoError(t, err)
	linkPub, _, err := ks.GenerateKeyPair()
	require.NoError(t, err)

	base := func() map[string]interface{} {
		return map[string]interface{}{
			"Identifier":        "auth1",
			"IdentityPublicKey": signpem.ToPublicPEMString(idPub),
			"WireKEMScheme":     ks.Name(),
			"LinkPublicKey":     kempem.ToPublicPEMString(linkPub),
			"Addresses":         []interface{}{"tcp://127.0.0.1:1234"},
		}
	}

	t.Run("omitted-inherits-default", func(t *testing.T) {
		data := base()
		var a Authority
		require.NoError(t, a.UnmarshalTOML(data))
		require.Equal(t, DefaultPKISignatureScheme, a.PKISignatureScheme)
	})

	t.Run("empty-inherits-default", func(t *testing.T) {
		data := base()
		data["PKISignatureScheme"] = ""
		var a Authority
		require.NoError(t, a.UnmarshalTOML(data))
		require.Equal(t, DefaultPKISignatureScheme, a.PKISignatureScheme)
	})

	t.Run("unknown-scheme-errors", func(t *testing.T) {
		data := base()
		data["PKISignatureScheme"] = "no-such-scheme"
		var a Authority
		require.Error(t, a.UnmarshalTOML(data))
	})
}
