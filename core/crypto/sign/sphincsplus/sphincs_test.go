package sphincsplus

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignatureScheme(t *testing.T) {
	t.Parallel()
	privKey, pubKey := Scheme.NewKeypair()
	message := []byte("i am a message")
	sig := privKey.Sign(message)
	require.True(t, pubKey.Verify(sig, message))
}

func TestSerialization(t *testing.T) {
	t.Parallel()
	privKey, pubKey := Scheme.NewKeypair()
	message := []byte("i am a message")
	sig := privKey.Sign(message)

	pubKeyBytes := pubKey.Bytes()
	pubKey2 := NewEmptyPublicKey()
	err := pubKey2.FromBytes(pubKeyBytes)
	require.NoError(t, err)

	pubKey2Bytes := pubKey2.Bytes()
	require.Equal(t, pubKey2Bytes, pubKeyBytes)

	require.True(t, pubKey2.Verify(sig, message))
}

func TestSizes(t *testing.T) {
	t.Parallel()
	privKey, pubKey := Scheme.NewKeypair()
	message := []byte("i am a message")
	sig := privKey.Sign(message)
	require.True(t, pubKey.Verify(sig, message))

	t.Logf("privKey len %d", len(privKey.Bytes()))
	t.Logf("pubKey len %d", len(pubKey.Bytes()))
	t.Logf("sig len %d", len(sig))

	require.Equal(t, len(privKey.Bytes()), Scheme.PrivateKeySize())
	require.Equal(t, len(pubKey.Bytes()), Scheme.PublicKeySize())
	require.Equal(t, len(sig), Scheme.SignatureSize())
}
