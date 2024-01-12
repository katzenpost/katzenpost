package CTIDH2048X25519

import (
	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/crypto/nike/hybrid"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ctidh2048"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

var CTIDH2048X25519 nike.Scheme = hybrid.New(
	"CTIDH2048-X25519",
	ctidh2048.CTIDH2048Scheme,
	ecdh.NewEcdhNike(rand.Reader),
)
