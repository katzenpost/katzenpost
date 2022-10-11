package sphincsplus

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignatureScheme(t *testing.T) {
	privKey, pubKey := Scheme.NewKeypair()
	message := []byte("i am a message")
	sig := privKey.Sign(message)
	require.True(t, pubKey.Verify(sig, message))
}

func TestSerialization(t *testing.T) {
	privKey, pubKey := Scheme.NewKeypair()
	message := []byte("i am a message")
	sig := privKey.Sign(message)

	pubKeyBytes := pubKey.Bytes()
	pubKey2 := new(publicKey)
	err := pubKey2.FromBytes(pubKeyBytes)
	require.NoError(t, err)

	pubKey2Bytes := pubKey2.Bytes()
	require.Equal(t, pubKey2Bytes, pubKeyBytes)

	require.True(t, pubKey2.Verify(sig, message))
}
