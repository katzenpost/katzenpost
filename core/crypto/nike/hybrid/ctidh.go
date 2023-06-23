//go:build ctidh
// +build ctidh

package hybrid

import (
	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ctidh"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

var CTIDH1024X25519 nike.Scheme = &scheme{
	name:   "CTIDH1024-X25519",
	first:  ctidh.CTIDH1024Scheme,
	second: ecdh.NewEcdhNike(rand.Reader),
}
