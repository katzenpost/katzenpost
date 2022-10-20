package cert

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/crypto/pem"
)

func TestToFromPEM(t *testing.T) {
	verifyKeyString1 := `-----BEGIN ED25519 SPHINCS+ PUBLIC KEY-----
3zXGXWKZeW7cgLRKZPeF73Yi0+J+BtEzfoHM1SXMqdB30p0iAy1JDzaLWPOdAJNq
jWmeAbCVBJkDkRtdzghri6me5ZgEwQ3tr/OVK2Podxl3dIKP+riONi3po+D57ryg
-----END ED25519 SPHINCS+ PUBLIC KEY-----
`
	_, pubKey := Scheme.NewKeypair()

	err := pem.FromPEMString(verifyKeyString1, pubKey)
	require.NoError(t, err)

	verifyKeyString2 := string(pem.ToPEMBytes(pubKey))
	require.Equal(t, verifyKeyString1, verifyKeyString2)
}
