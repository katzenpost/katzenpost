package schemes

import (
	"testing"

	"github.com/cloudflare/circl/kem"
	"github.com/stretchr/testify/require"
)

func testScheme(t *testing.T, s kem.Scheme) {
	t.Logf("ciphertext size %d", s.CiphertextSize())
	t.Logf("shared key size %d", s.SharedKeySize())
	t.Logf("private key size %d", s.PrivateKeySize())
	t.Logf("public key size %d", s.PublicKeySize())
	t.Logf("seed size %d", s.SeedSize())
	t.Logf("encapsulation seed size %d", s.EncapsulationSeedSize())

	pubkey1, privkey1, err := s.GenerateKeyPair()
	require.NoError(t, err)
	ct1, ss1, err := s.Encapsulate(pubkey1)
	require.NoError(t, err)
	ss1b, err := s.Decapsulate(privkey1, ct1)
	require.NoError(t, err)

	t.Logf("our shared key is %x", ss1)
	t.Logf("our shared key is %x", ss1b)

	require.Equal(t, ss1, ss1b) // XXX

	ct2, ss2, err := s.Encapsulate(pubkey1)
	require.NoError(t, err)
	require.NotEqual(t, ct1, ct2)
	require.NotEqual(t, ss1, ss2)

}

func TestSchemes(t *testing.T) {
	schemes := All()
	for name, s := range schemes {
		t.Logf("Testing %s ----------------------------------", name)
		testScheme(t, s)
	}
}
