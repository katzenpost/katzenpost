package ed25519sphincsplus

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEddsaSphincsplusScheme(t *testing.T) {
	t.Parallel()
	message := []byte("hello world")
	privKey, pubKey := Scheme.NewKeypair()
	signature := privKey.Sign(message)
	require.Equal(t, len(signature), Scheme.SignatureSize())
	ok := pubKey.Verify(signature, message)
	require.True(t, ok)

}

func TestEddsaSphincsplusSchemeTextUnmarshaler(t *testing.T) {
	t.Parallel()
	message := []byte("hello world")
	privKey, pubKey := Scheme.NewKeypair()

	pubKeyText, err := pubKey.MarshalText()
	require.NoError(t, err)

	pubKey2, err := Scheme.UnmarshalTextPublicKey(pubKeyText)
	require.NoError(t, err)

	signature := privKey.Sign(message)
	ok := pubKey.Verify(signature, message)
	require.True(t, ok)

	ok = pubKey2.Verify(signature, message)
	require.True(t, ok)
}

func TestEddsaSphincsplusSchemeBinaryUnmarshaler(t *testing.T) {
	t.Parallel()
	message := []byte("hello world")
	privKey, pubKey := Scheme.NewKeypair()

	pubKeyBytes, err := pubKey.MarshalBinary()
	require.NoError(t, err)

	pubKey2, err := Scheme.UnmarshalBinaryPublicKey(pubKeyBytes)
	require.NoError(t, err)

	signature := privKey.Sign(message)
	ok := pubKey.Verify(signature, message)
	require.True(t, ok)

	ok = pubKey2.Verify(signature, message)
	require.True(t, ok)
}
