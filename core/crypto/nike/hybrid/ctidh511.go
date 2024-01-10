//go:build ctidh511

package hybrid

import (
	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ctidh511"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

var CTIDH511X25519 nike.Scheme = &scheme{
	name:   "CTIDH511-X25519",
	first:  ctidh511.CTIDH511Scheme,
	second: ecdh.NewEcdhNike(rand.Reader),
}
