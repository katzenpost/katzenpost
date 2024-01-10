//go:build ctidh512

package hybrid

import (
	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ctidh512"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

var CTIDH512X25519 nike.Scheme = &scheme{
	name:   "CTIDH512-X25519",
	first:  ctidh512.CTIDH512Scheme,
	second: ecdh.NewEcdhNike(rand.Reader),
}
