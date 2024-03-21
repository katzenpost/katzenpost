package wire

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"
)

var testingSchemeName = "x25519"
var testingScheme = schemes.ByName(testingSchemeName)

func TestKEMTextUnmarshal(t *testing.T) {
	s := schemes.ByName("Kyber768-X25519")

	pubkey, _, err := s.GenerateKeyPair()
	require.NoError(t, err)

	blob1, err := pubkey.MarshalText()
	require.NoError(t, err)

	testpubkey2, err := s.UnmarshalTextPublicKey([]byte(blob1))
	require.NoError(t, err)

	blob2, err := testpubkey2.MarshalText()
	require.NoError(t, err)

	require.Equal(t, blob1, blob2)
}

func TestKEMMarshalingShouldFailButDoesNotFail(t *testing.T) {
	linkPubKey, linkPrivKey, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)

	linkPrivKeyBlob := pem.ToPrivatePEMBytes(linkPrivKey)
	linkPubKeyBlob := pem.ToPublicPEMBytes(linkPubKey)

	linkPrivKey2, err := pem.FromPrivatePEMBytes(linkPrivKeyBlob, testingScheme)
	require.NoError(t, err)

	linkPubKey2, err := pem.FromPublicPEMBytes(linkPubKeyBlob, testingScheme)
	require.NoError(t, err)

	require.True(t, linkPubKey.Equal(linkPubKey2))
	require.True(t, linkPrivKey.Equal(linkPrivKey2))

	linkPrivKeyBlob2 := pem.ToPrivatePEMBytes(linkPrivKey2)
	linkPubKeyBlob2 := pem.ToPublicPEMBytes(linkPubKey2)

	require.Equal(t, linkPrivKeyBlob, linkPrivKeyBlob2)
	require.Equal(t, linkPubKeyBlob, linkPubKeyBlob2)
}

func TestKEMPEMFiles(t *testing.T) {
	dir := t.TempDir()

	linkpriv := filepath.Join(dir, "link.private.pem")
	linkpub := filepath.Join(dir, "link.pubate.pem")

	linkPubKey, linkPrivKey, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)

	err = pem.PrivateKeyToFile(linkpriv, linkPrivKey)
	require.NoError(t, err)

	err = pem.PublicKeyToFile(linkpub, linkPubKey)
	require.NoError(t, err)

	linkPrivKey2, err := pem.FromPrivatePEMFile(linkpriv, testingScheme)
	require.NoError(t, err)

	linkPubKey2, err := pem.FromPublicPEMFile(linkpub, testingScheme)
	require.NoError(t, err)

	require.True(t, linkPrivKey.Equal(linkPrivKey2))
	require.True(t, linkPubKey.Equal(linkPubKey2))
}
