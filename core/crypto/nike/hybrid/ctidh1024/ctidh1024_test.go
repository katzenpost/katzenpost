package CTIDH1024X25519

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHybridCTIDH1024X25519(t *testing.T) {
	scheme := CTIDH1024X25519

	alicePublicKey, alicePrivateKey, err := scheme.GenerateKeyPair()
	require.NoError(t, err)

	tmp := scheme.DerivePublicKey(alicePrivateKey)
	require.Equal(t, alicePublicKey.Bytes(), tmp.Bytes())

	bobPubKey, bobPrivKey, err := scheme.GenerateKeyPair()
	require.NoError(t, err)

	aliceS := scheme.DeriveSecret(alicePrivateKey, bobPubKey)

	bobS := scheme.DeriveSecret(bobPrivKey, alicePublicKey)
	require.Equal(t, bobS, aliceS)
}
