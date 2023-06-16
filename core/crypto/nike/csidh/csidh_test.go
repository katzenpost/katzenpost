//go:build !ppc64le

package csidh

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCtidhNike(t *testing.T) {
	scheme := NOBS_CSIDH512Scheme

	alicePublicKey, alicePrivateKey, err := scheme.GenerateKeyPair()
	require.NoError(t, err)

	tmp := scheme.DerivePublicKey(alicePrivateKey.(*PrivateKey))
	require.Equal(t, alicePublicKey.Bytes(), tmp.Bytes())

	bobPubKey, bobPrivKey, err := scheme.GenerateKeyPair()
	require.NoError(t, err)

	aliceS := scheme.DeriveSecret(alicePrivateKey, bobPubKey)

	bobS := scheme.DeriveSecret(bobPrivKey, alicePublicKey.(*PublicKey))
	require.Equal(t, bobS, aliceS)
}
