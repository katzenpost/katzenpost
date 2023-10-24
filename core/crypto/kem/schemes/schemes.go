package schemes

import (
	"strings"

	"github.com/katzenpost/circl/kem"
	"github.com/katzenpost/circl/kem/kyber/kyber768"
	mceliece "github.com/katzenpost/circl/kem/mceliece/mceliece460896"

	"github.com/katzenpost/katzenpost/core/crypto/kem/adapter"
	kemhybrid "github.com/katzenpost/katzenpost/core/crypto/kem/hybrid"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

var allSchemes = [...]kem.Scheme{
	adapter.FromNIKE(ecdh.NewEcdhNike(rand.Reader)),
	// Must build with `ctidh` build tag (and other supporting env vars)
	// for CTIDH usage:
	// adapter.FromNIKE(hybrid.CTIDH1024X25519),
	//kemhybrid.New(
	//	"Kyber1024-CTIDH1024-X25519",
	//	adapter.FromNIKE(hybrid.CTIDH1024X25519),
	//	kyber1024.Scheme(),
	//),
	kemhybrid.New(
		"Kyber768-X25519",
		adapter.FromNIKE(ecdh.NewEcdhNike(rand.Reader)),
		kyber768.Scheme(),
	),

	kemhybrid.New(
		"McEliece-X25519",
		adapter.FromNIKE(ecdh.NewEcdhNike(rand.Reader)),
		mceliece.Scheme(),
	),
}

var allSchemeNames map[string]kem.Scheme

func init() {
	allSchemeNames = make(map[string]kem.Scheme)
	for _, scheme := range allSchemes {
		allSchemeNames[strings.ToLower(scheme.Name())] = scheme
	}
}

// ByName returns the NIKE scheme by string name.
func ByName(name string) kem.Scheme {
	return allSchemeNames[strings.ToLower(name)]
}

// All returns all NIKE schemes supported.
func All() []kem.Scheme {
	a := allSchemes
	return a[:]
}
