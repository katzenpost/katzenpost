package CTIDH1024X25519

import (
	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/crypto/nike/hybrid"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ctidh1024"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

var CTIDH1024X25519 nike.Scheme = hybrid.New(
	"CTIDH1024-X25519",
	ctidh1024.CTIDH1024Scheme,
	ecdh.NewEcdhNike(rand.Reader),
)
