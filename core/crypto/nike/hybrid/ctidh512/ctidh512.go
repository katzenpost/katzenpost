package CTIDH512X25519

import (
	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/crypto/nike/hybrid"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ctidh512"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

var CTIDH512X25519 nike.Scheme = hybrid.New(
	"CTIDH512-X25519",
	ctidh512.CTIDH512Scheme,
	ecdh.NewEcdhNike(rand.Reader),
)
