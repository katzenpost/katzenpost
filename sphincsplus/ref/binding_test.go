package sphincsplus

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignVerify(t *testing.T) {
	t.Parallel()
	privKey1, pubKey1 := NewKeypair()
	message := []byte("i am a message")
	sig1 := privKey1.Sign(message)
	require.True(t, pubKey1.Verify(sig1, message))

	privKey2, pubKey2 := NewKeypair()
	require.False(t, pubKey2.Verify(sig1, message))

	sig2 := privKey2.Sign(message)
	require.True(t, pubKey2.Verify(sig2, message))
	require.False(t, pubKey1.Verify(sig2, message))

	// non-determinism
	sig3 := privKey1.Sign(message)
	require.NotEqual(t, sig1, sig3)
}

func TestSerialization(t *testing.T) {
	t.Parallel()
	privKey1, pubKey1 := NewKeypair()
	message := []byte("i am a message")
	sig := privKey1.Sign(message)
	require.True(t, pubKey1.Verify(sig, message))

	pubKeyBytes1 := pubKey1.Bytes()
	pubKey2 := &PublicKey{}
	err := pubKey2.FromBytes(pubKeyBytes1)
	require.NoError(t, err)
	require.True(t, pubKey2.Verify(sig, message))
	require.False(t, pubKey2.Verify(sig, message[:len(message)-3]))

	privKeyBytes2 := privKey1.Bytes()
	privKey2 := &PrivateKey{}
	err = privKey2.FromBytes(privKeyBytes2)
	require.NoError(t, err)
	sig2 := privKey2.Sign(message)
	require.True(t, pubKey1.Verify(sig2, message))
	require.True(t, pubKey2.Verify(sig2, message))
}

func TestSizes(t *testing.T) {
	t.Parallel()
	privKey, pubKey := NewKeypair()
	message := []byte("i am a message")
	sig := privKey.Sign(message)
	require.True(t, pubKey.Verify(sig, message))

	require.Equal(t, PrivateKeySize, len(privKey.Bytes()))
	require.Equal(t, PublicKeySize, len(pubKey.Bytes()))
	require.Equal(t, SignatureSize, len(sig))

	t.Logf("PrivateKeySize %d", PrivateKeySize)
	t.Logf("PublicKeySize %d", PublicKeySize)
	t.Logf("SignatureSize %d", SignatureSize)
}
