// Cached replica envelope keypair fixtures for fast tests. Generated once
// per test binary run (McEliece348864-X25519 keygen is comparatively slow,
// unlike the old CTIDH fixtures this file used to pre-bake as hex literals)
// and reused across every test that needs replica keypairs, rather than
// paying keygen cost per test case.

package client

import (
	"sync"

	"github.com/katzenpost/hpqc/kem"

	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

type ctidhFixture struct {
	Pub      kem.PublicKey
	Priv     kem.PrivateKey
	PubBytes []byte
}

var (
	ctidhFixtures     [8]ctidhFixture
	ctidhFixturesOnce sync.Once
)

func loadCTIDHFixtures() {
	ctidhFixturesOnce.Do(func() {
		for i := range ctidhFixtures {
			pub, priv, err := replicaCommon.KEMScheme.GenerateKeyPair()
			if err != nil {
				panic(err)
			}
			pubBytes, err := pub.MarshalBinary()
			if err != nil {
				panic(err)
			}
			ctidhFixtures[i] = ctidhFixture{
				Pub:      pub,
				Priv:     priv,
				PubBytes: pubBytes,
			}
		}
	})
}
