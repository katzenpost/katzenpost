package wire

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"
)

func TestToFromPEM(t *testing.T) {
	linkPemString1 := `-----BEGIN KYBER768-X25519 PUBLIC KEY-----
+WOSbmi5nJWBFx/FePcx+46MindcROtr7mMuS5aJE0r2Z6mIXASEOc5hASZZ4SDs
lRU1URiBoKQRFRM0UmzgJjpUMhm4miM0ShCwJEEV1RWW5AF+1RlHa2PC7En5gI4O
prOWNZdhIYp89FMTxIHGYkGD0raREhJisDHmyWvr+jl4qx53a5vIygrCyM3AK4Sp
M1vB15jzFwRSS4JiM0ooc8vla0FIgR09JYXrE8y+zCw/8a7qcEM/6iNHeCzVsw7S
WYC1+Jc4h6CRkHXRNaohCRtSFJ4MeBYdqp5bVmtgh5CXtSi74V368D6kG2mHwVHJ
+Af3WopXkbduM4RiBBen+3s0ZRkH0MSNtzVfdZ332my1xwXVa8Z4C7mWjGRhkULM
uybp2IFvZB59oSnqzCbTgcf+Klnvy2isIg+OAJ+7u4wtYoWd1TTDogYNpj+COzhs
xhdjA4PWN1QkxnO3QaUfIh7OvHjtypQ3qMbX1C1d1bhK0SekJwutKSFFMHJuNTLQ
iqtKEjAnm1FQV8rBA7TqZHHQEFOVRSrJhYiZBSMpJX5qgxhvFjhJ0YHmaw5WxaDl
K3hXw4GIW691YSeOGCWUYVEmy6+1w48ciKzLhKd7ab5XcU9WKidQIYKuxmRC1Y9c
YQlYQ2Qew64vOo4naz3Xt8dViGq3MrLIp8pN10ZNaZpBecWpU8hruof3iDfVgijU
pMCCIAFk1J894H0sdgCVdMmYZy0FM1KZSkKh5cAtusIzJ7YomZuzsEmvJ7UZdJTY
FS6BEBQLAw0t+UTdmFeABpovJhB890/rQQDYGSqZo3954AdrU8aFYj9hRwax/KvL
8lqpuQCORpDo0k7RF1XEF2i9Zwmbx2VZGnrtyWV8JZzyo61GrF4ydCx0qU0ZWWhB
/CsnF6iytyOUtAcvMTGuO5rRAcnusblV6JQ+NLC6icHFd4MDpw9zBCrX4AZQWnGl
VoyCTM7dCnBLtUmhdqZX82HvlSO8xZrc3IEkQImA2qRxtJjv0VugSB8W941JYo9w
zGFofH5qdm2xqx31ya3zWZ2aEk8GkslSpMteU8nEs7GhS5Y7kQtvSEjIhrzfMi3A
WT5tyFRzeIWww2sspF5s2m3JxYu+15zLV0oRHI8KxmEK+HorShLHZnGazDO/BxFH
oJc7YyTt+U54NSnL4XhieSkoJ1NwTFLQcGhvcjFuNTGdc1Db2mEWS68DBXvHhmy7
qnsVEyowzHtCfKNHqcJIsmIO9jHiBHZ7B7f7GsUMpGlzBjQI3B5Z1XYgQVcTlX/k
MW3W0Ih4DFFkBJ3X5RR7gskjdnxHqjrfmRLMlTqa/BdAlTZc3F6Y11jqCKzZxT/c
pyAyWDOYyT9jkmQ5kABVsi5QkXo2YWg8ihklmbskFhYliU3NxWfra0SZDHIWERCa
qUcdy8ySAEtRrJIN2KgpZHoRxW9SC8WJ+BNg1kKxtAw3oiSkgV3PNaEwjCp1iqth
BSQKkgoVKEZYJzU6usiderfdGZfQUmp/oA5EGhgVp7O5yXfauHKGay++YMFFs4W7
rJoEjFXoChJF5xWicIVxi0F3k6KTZYTCus+SlMJkVLFwmf9Ui+rDIqVwJ1C6tzKm
7pZc295vLdQ4w4gOVmGd9w==
-----END KYBER768-X25519 PUBLIC KEY-----
`
	s := schemes.ByName("Kyber768-X25519")
	key1, err := pem.FromPublicPEMString(linkPemString1, s)
	require.NoError(t, err)

	blob1 := pem.ToPublicPEMBytes(key1)
	require.Equal(t, string(linkPemString1), string(blob1))

	key2, err := s.UnmarshalTextPublicKey([]byte(linkPemString1))
	require.NoError(t, err)

	blob2, err := key2.MarshalText()
	require.NoError(t, err)

	require.Equal(t, blob1, blob2)
}

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
	linkPubKey, linkPrivKey, err := DefaultScheme.GenerateKeyPair()
	require.NoError(t, err)

	linkPrivKeyBlob := pem.ToPrivatePEMBytes(linkPrivKey)
	linkPubKeyBlob := pem.ToPublicPEMBytes(linkPubKey)

	linkPrivKey2, err := pem.FromPrivatePEMBytes(linkPrivKeyBlob, DefaultScheme)
	require.NoError(t, err)

	linkPubKey2, err := pem.FromPublicPEMBytes(linkPubKeyBlob, DefaultScheme)
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

	linkPubKey, linkPrivKey, err := DefaultScheme.GenerateKeyPair()
	require.NoError(t, err)

	err = pem.PrivateKeyToFile(linkpriv, linkPrivKey)
	require.NoError(t, err)

	err = pem.PublicKeyToFile(linkpub, linkPubKey)
	require.NoError(t, err)

	linkPrivKey2, err := pem.FromPrivatePEMFile(linkpriv, DefaultScheme)
	require.NoError(t, err)

	linkPubKey2, err := pem.FromPublicPEMFile(linkpub, DefaultScheme)
	require.NoError(t, err)

	require.True(t, linkPrivKey.Equal(linkPrivKey2))
	require.True(t, linkPubKey.Equal(linkPubKey2))
}
