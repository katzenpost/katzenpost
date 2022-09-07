// config_test.go - Voting authority configuration file parser tests.
// Copyright (C) 2021  Masala
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

var linkPubKeyPem = `-----BEGIN Kyber768-X25519 PUBLIC KEY-----
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
-----END Kyber768-X25519 PUBLIC KEY-----
`

func TestParseVotingConfig(t *testing.T) {
	require := require.New(t)
	fn, err := filepath.Abs("../../../cmd/voting/authority.toml.sample")
	require.NoError(err)

	os.Mkdir("/tmp/katzenpost-authority/", 0777)
	err = os.WriteFile("/tmp/katzenpost-authority/auth1_link_pub.pem", []byte(linkPubKeyPem), 0666)
	require.NoError(err)
	err = os.WriteFile("/tmp/katzenpost-authority/auth2_link_pub.pem", []byte(linkPubKeyPem), 0666)
	require.NoError(err)
	err = os.WriteFile("/tmp/katzenpost-authority/auth3_link_pub.pem", []byte(linkPubKeyPem), 0666)
	require.NoError(err)

	// get the configuration object and verify that the sample
	// configuration file is valid
	cfg, err := LoadFile(fn, false)
	require.NoError(err)
	require.NotNil(cfg)
	require.Equal(3, len(cfg.Topology.Layers))
	for _, l := range cfg.Topology.Layers {
		require.Equal(1, len(l.Nodes))
	}
}
