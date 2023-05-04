package schemes

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHybridKEM(t *testing.T) {
	s := ByName("Kyber768-X25519")
	pubkey1, privkey1, err := s.GenerateKeyPair()
	require.NoError(t, err)
	ct, ss, err := s.Encapsulate(pubkey1)
	require.NoError(t, err)
	ss2, err := s.Decapsulate(privkey1, ct)
	require.NoError(t, err)
	require.Equal(t, ss, ss2)
	t.Logf("our shared key is %x", ss)
}
