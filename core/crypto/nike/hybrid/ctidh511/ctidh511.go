package CTIDH511X25519

import (
	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/crypto/nike/hybrid"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ctidh511"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

var CTIDH511X25519 nike.Scheme = hybrid.New(
    "CTIDH511-X25519",
	ctidh511.CTIDH511Scheme,
	ecdh.NewEcdhNike(rand.Reader),
)
