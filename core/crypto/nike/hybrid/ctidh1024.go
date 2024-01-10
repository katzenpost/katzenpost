//go:build ctidh1024

package hybrid

import (
	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ctidh1024"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

var CTIDH1024X25519 nike.Scheme = &scheme{
	name:   "CTIDH1024-X25519",
	first:  ctidh1024.CTIDH1024Scheme,
	second: ecdh.NewEcdhNike(rand.Reader),
}
