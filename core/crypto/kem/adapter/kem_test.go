package adapter

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

func TestNikeToKemAdapter(t *testing.T) {
	ecdhNike := ecdh.NewEcdhNike(rand.Reader)
	s := FromNIKE(ecdhNike)

	t.Logf("hello my name is %s", s.Name())

	pubkey1, privkey1, err := s.GenerateKeyPair()
	require.NoError(t, err)

	ct, ss, err := s.Encapsulate(pubkey1)
	require.NoError(t, err)

	ss2, err := s.Decapsulate(privkey1, ct)
	require.NoError(t, err)

	require.Equal(t, ss, ss2)

	t.Logf("our shared key is %x", ss)
}
