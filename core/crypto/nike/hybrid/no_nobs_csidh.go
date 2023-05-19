//go:build armbe || arm64be || ppc64 || mips || mips64 || mips64p32 || s390 || s390x || sparc || sparc64
// +build armbe arm64be ppc64 mips mips64 mips64p32 s390 s390x sparc sparc64

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
