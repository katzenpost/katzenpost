//go:build ppc64
// +build ppc64

package hybrid

import (
	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

var NOBS_CSIDHX25519 nike.Scheme = &scheme{
	name:   "NOBS_CSIDH-X25519",
	first:  ecdh.NewEcdhNike(rand.Reader),
	second: nil,
}
