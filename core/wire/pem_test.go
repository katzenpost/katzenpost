package wire

import (
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
	mypublicKey, err := pem.FromPublicPEMString(linkPemString1, s)
	require.NoError(t, err)

	linkPemString2 := pem.ToPublicPEMBytes(mypublicKey)
	require.Equal(t, string(linkPemString1), string(linkPemString2))

	//

	testpubkey, _, err := s.GenerateKeyPair()
	require.NoError(t, err)

	err = testpubkey.UnmarshalText([]byte(linkPemString1))
	require.NoError(t, err)

	blob0, err := testpubkey.MarshalText()
	require.NoError(t, err)

	t.Logf("%s", blob0)
}

func TestKEMTextUnmarshal(t *testing.T) {
	s := schemes.ByName("Kyber768")

	testpubkey2, _, err := s.GenerateKeyPair()
	require.NoError(t, err)

	pubkey, _, err := s.GenerateKeyPair()
	require.NoError(t, err)

	blob1, err := pubkey.MarshalText()
	require.NoError(t, err)

	err = testpubkey2.UnmarshalText(blob1)
	require.NoError(t, err)

	blob2, err := testpubkey2.MarshalText()
	require.NoError(t, err)

	require.Equal(t, blob1, blob2)
}
