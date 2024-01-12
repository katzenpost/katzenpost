//go:build ctidh2048

package hybrid

import (
	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ctidh2048"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

var CTIDH2048X25519 nike.Scheme = &scheme{
	name:   "CTIDH2048-X25519",
	first:  ctidh2048.CTIDH2048Scheme,
	second: ecdh.NewEcdhNike(rand.Reader),
}
