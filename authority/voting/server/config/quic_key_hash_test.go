// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	kempem "github.com/katzenpost/hpqc/kem/pem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"
)

func quicKeyHashAuthority(t *testing.T) map[string]interface{} {
	t.Helper()
	ss := signschemes.ByName(testSchemeName)
	ks := kemschemes.ByName("Xwing")
	idPub, _, err := ss.GenerateKey()
	require.NoError(t, err)
	linkPub, _, err := ks.GenerateKeyPair()
	require.NoError(t, err)
	return map[string]interface{}{
		"Identifier":         "auth1",
		"PKISignatureScheme": ss.Name(),
		"IdentityPublicKey":  signpem.ToPublicPEMString(idPub),
		"WireKEMScheme":      ks.Name(),
		"LinkPublicKey":      kempem.ToPublicPEMString(linkPub),
		"Addresses":          []interface{}{"quic://127.0.0.1:1234"},
	}
}

func TestAuthorityReadsItsQUICKeyHash(t *testing.T) {
	want := bytes.Repeat([]byte{0xa5}, 32)
	data := quicKeyHashAuthority(t)
	data["QUICKeyHash"] = hex.EncodeToString(want)
	var a Authority
	require.NoError(t, a.UnmarshalTOML(data))
	require.Equal(t, want, []byte(a.QUICKeyHash), "an authority entry dropped its QUICKeyHash")

	var buf bytes.Buffer
	require.NoError(t, toml.NewEncoder(&buf).Encode(struct{ Authorities []*Authority }{[]*Authority{&a}}))
	var decoded struct{ Authorities []*Authority }
	_, err := toml.Decode(buf.String(), &decoded)
	require.NoError(t, err)
	require.Equal(t, want, []byte(decoded.Authorities[0].QUICKeyHash), "a QUICKeyHash did not survive a TOML round trip")
}

func TestAuthorityWithoutAQUICKeyHashWritesNone(t *testing.T) {
	var a Authority
	require.NoError(t, a.UnmarshalTOML(quicKeyHashAuthority(t)))
	require.Nil(t, a.QUICKeyHash)
	var buf bytes.Buffer
	require.NoError(t, toml.NewEncoder(&buf).Encode(struct{ Authorities []*Authority }{[]*Authority{&a}}))
	require.False(t, strings.Contains(buf.String(), "QUICKeyHash"), "an authority without a QUICKeyHash wrote one:\n%s", buf.String())
}

func TestAuthorityRejectsAMalformedQUICKeyHash(t *testing.T) {
	for name, value := range map[string]interface{}{
		"short":   hex.EncodeToString(bytes.Repeat([]byte{1}, 31)),
		"long":    hex.EncodeToString(bytes.Repeat([]byte{1}, 33)),
		"not hex": strings.Repeat("zz", 32),
		"empty":   "",
		"number":  int64(7),
	} {
		t.Run(name, func(t *testing.T) {
			data := quicKeyHashAuthority(t)
			data["QUICKeyHash"] = value
			var a Authority
			require.Error(t, a.UnmarshalTOML(data), "an authority entry accepted QUICKeyHash %v", value)
		})
	}
}
