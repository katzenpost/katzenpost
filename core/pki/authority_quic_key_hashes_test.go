// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
)

const authorityQUICKeyHashesKey = "AuthorityQUICKeyHashes"

func signedWithAuthorityQUICKeyHashes(t *testing.T, priv sign.PrivateKey, pub sign.PublicKey, entries map[[PublicKeyHashSize]byte][]byte) []byte {
	t.Helper()
	d := weeklySRVDoc()
	d.Epoch, _, _ = epochtime.Now()
	d.GenesisEpoch = d.Epoch - 1
	d.PKISignatureScheme = pub.Scheme().Name()
	payload, err := ccbor.Marshal((*document)(d))
	require.NoError(t, err)
	var fields map[string]cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(payload, &fields))
	encoded, err := ccbor.Marshal(entries)
	require.NoError(t, err)
	fields[authorityQUICKeyHashesKey] = encoded
	payload, err = ccbor.Marshal(fields)
	require.NoError(t, err)
	signed, err := cert.Sign(priv, pub, payload, d.Epoch+5)
	require.NoError(t, err)
	return signed
}

func TestAuthorityQUICKeyHashesSurviveReencoding(t *testing.T) {
	pub, priv, err := signSchemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	pk := hash.Sum256From(pub)
	signed := signedWithAuthorityQUICKeyHashes(t, priv, pub, map[[PublicKeyHashSize]byte][]byte{pk: make([]byte, 3*QUICKeyHashSize)})

	d, err := ParseDocument(signed)
	require.NoError(t, err)
	reencoded, err := d.MarshalCertificate()
	require.NoError(t, err)
	require.True(t, bytes.Equal(signed, reencoded), "a consensus carrying authority QUIC key hashes changed when re-encoded: %d bytes signed, %d re-encoded", len(signed), len(reencoded))
	_, err = FromPayload(pub, reencoded)
	require.NoError(t, err)
}

func TestAuthorityQUICKeyHashesWellFormed(t *testing.T) {
	pub, priv, err := signSchemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	pk := hash.Sum256From(pub)
	otherPub, _, err := signSchemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	other := hash.Sum256From(otherPub)
	cases := []struct {
		name    string
		entries map[[PublicKeyHashSize]byte][]byte
		ok      bool
	}{
		{"one", map[[PublicKeyHashSize]byte][]byte{pk: make([]byte, 32)}, true},
		{"three", map[[PublicKeyHashSize]byte][]byte{pk: make([]byte, 96)}, true},
		{"empty", map[[PublicKeyHashSize]byte][]byte{pk: {}}, false},
		{"short", map[[PublicKeyHashSize]byte][]byte{pk: make([]byte, 31)}, false},
		{"four", map[[PublicKeyHashSize]byte][]byte{pk: make([]byte, 128)}, false},
		{"unknown authority", map[[PublicKeyHashSize]byte][]byte{other: make([]byte, 32)}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := ParseDocument(signedWithAuthorityQUICKeyHashes(t, priv, pub, c.entries))
			require.NoError(t, err)
			err = IsVoteWellFormed(d, []sign.PublicKey{pub})
			if c.ok {
				require.NoError(t, err)
				return
			}
			require.Error(t, err, fmt.Sprintf("%s: a malformed authority QUIC key hash was accepted", c.name))
		})
	}
}
