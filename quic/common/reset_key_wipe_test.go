// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"bytes"
	"crypto"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/sign"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"
)

type copyingIdentityKey struct {
	sign.PrivateKey
	identitySecret []byte
	handedOut      [][]byte
}

func (k *copyingIdentityKey) MarshalBinary() ([]byte, error) {
	identitySecretCopy := bytes.Clone(k.identitySecret)
	k.handedOut = append(k.handedOut, identitySecretCopy)
	return identitySecretCopy, nil
}

func (k *copyingIdentityKey) Public() crypto.PublicKey { return k.PrivateKey.Public() }

func (k *copyingIdentityKey) Sign(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
	return k.PrivateKey.Sign(r, d, o)
}

func TestStatelessResetKeyWipesTheMarshalledIdentityKey(t *testing.T) {
	_, identityPrivateKey, err := signschemes.ByName(testIdentityScheme).GenerateKey()
	require.NoError(t, err)
	identitySecret, err := identityPrivateKey.MarshalBinary()
	require.NoError(t, err)
	k := &copyingIdentityKey{PrivateKey: identityPrivateKey, identitySecret: bytes.Clone(identitySecret)}
	_, err = statelessResetKey(k)
	require.NoError(t, err)
	require.NotEmpty(t, k.handedOut)
	for _, identitySecretCopy := range k.handedOut {
		require.Equal(t, make([]byte, len(identitySecretCopy)), identitySecretCopy, "statelessResetKey left the marshalled identity key in memory")
	}
}

func TestStatelessResetKeyLeavesTheIdentityKeyIntact(t *testing.T) {
	for _, name := range []string{"Ed25519", testIdentityScheme} {
		_, identityPrivateKey, err := signschemes.ByName(name).GenerateKey()
		require.NoError(t, err)
		identitySecret, err := identityPrivateKey.MarshalBinary()
		require.NoError(t, err)
		identitySecret = bytes.Clone(identitySecret)
		resetKey, err := statelessResetKey(identityPrivateKey)
		require.NoError(t, err)
		after, err := identityPrivateKey.MarshalBinary()
		require.NoError(t, err)
		require.Equal(t, identitySecret, after, "%s: statelessResetKey wiped the identity key itself", name)
		again, err := statelessResetKey(identityPrivateKey)
		require.NoError(t, err)
		require.Equal(t, *resetKey, *again, name)
	}
}
