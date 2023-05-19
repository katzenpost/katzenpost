//go:build !armbe && !arm64be && !ppc64 && !mips && !mips64 && !mips64p32 && !s390 && !s390x && !sparc && !sparc64
// +build !armbe,!arm64be,!ppc64,!mips,!mips64,!mips64p32,!s390,!s390x,!sparc,!sparc64

package csidh

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCtidhNike(t *testing.T) {
	scheme := CSIDHScheme

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
