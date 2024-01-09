package hybrid

import (
	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ctidh1024"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ctidh2048"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ctidh511"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ctidh512"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

var CTIDH511X25519 nike.Scheme = &scheme{
	name:   "CTIDH511-X25519",
	first:  ctidh511.CTIDH511Scheme,
	second: ecdh.NewEcdhNike(rand.Reader),
}

var CTIDH512X25519 nike.Scheme = &scheme{
	name:   "CTIDH512-X25519",
	first:  ctidh512.CTIDH512Scheme,
	second: ecdh.NewEcdhNike(rand.Reader),
}

var CTIDH1024X25519 nike.Scheme = &scheme{
	name:   "CTIDH1024-X25519",
	first:  ctidh1024.CTIDH1024Scheme,
	second: ecdh.NewEcdhNike(rand.Reader),
}

var CTIDH2048X25519 nike.Scheme = &scheme{
	name:   "CTIDH2048-X25519",
	first:  ctidh2048.CTIDH2048Scheme,
	second: ecdh.NewEcdhNike(rand.Reader),
}
