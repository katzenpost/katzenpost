// SPDX-License-Identifier: AGPL-3.0-only

package genconfig

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
)

type textlessKey struct{ sign.PublicKey }

type badTextKey struct {
	sign.PublicKey
	text []byte
	err  error
}

func (k badTextKey) MarshalText() ([]byte, error) { return k.text, k.err }

type fakeScheme struct {
	sign.Scheme
	wrap   func(sign.PublicKey) sign.PublicKey
	genErr error
}

func (s fakeScheme) GenerateKey() (sign.PublicKey, sign.PrivateKey, error) {
	if s.genErr != nil {
		return nil, nil, s.genErr
	}
	pub, priv, err := s.Scheme.GenerateKey()
	return s.wrap(pub), priv, err
}

func TestCheckWritableKeyRefusesUnwritableKeys(t *testing.T) {
	ed := signSchemes.ByName("Ed25519")
	for name, s := range map[string]fakeScheme{
		"no text encoding":   {Scheme: ed, wrap: func(p sign.PublicKey) sign.PublicKey { return textlessKey{p} }},
		"text is not pem":    {Scheme: ed, wrap: func(p sign.PublicKey) sign.PublicKey { return badTextKey{PublicKey: p, text: []byte("not pem")} }},
		"marshal fails":      {Scheme: ed, wrap: func(p sign.PublicKey) sign.PublicKey { return badTextKey{PublicKey: p, err: errors.New("no")} }},
		"key generation err": {Scheme: ed, genErr: errors.New("no")},
	} {
		require.Error(t, checkWritableKey(s), name)
	}
	require.NoError(t, checkWritableKey(ed))
}

func TestSetupGeometryAcceptsEverySchemeWithHpqcPEMText(t *testing.T) {
	for _, scheme := range signSchemes.All() {
		cfg := &Config{Nike: "x25519", NrLayers: 3, UserForwardPayloadLength: 2000, PkiSignatureScheme: scheme.Name()}
		require.NoError(t, SetupGeometry(&Katzenpost{}, cfg), scheme.Name())
	}
}

func TestSetupGeometryRefusesUnknownScheme(t *testing.T) {
	cfg := &Config{Nike: "x25519", NrLayers: 3, UserForwardPayloadLength: 2000, PkiSignatureScheme: "no such scheme"}
	require.Error(t, SetupGeometry(&Katzenpost{}, cfg))
}
