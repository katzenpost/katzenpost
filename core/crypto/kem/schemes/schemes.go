package schemes

import (
	"github.com/cloudflare/circl/kem"
	"strings"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"

	"github.com/katzenpost/katzenpost/core/crypto/kem/adapter"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/nike/hybrid"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

// NOTE(david): The CTIDH schemes won't work unless you build with
// "ctidh" build tag.
var allSchemes = [...]kem.Scheme{
	adapter.FromNIKE(ecdh.NewEcdhNike(rand.Reader)),
	adapter.FromNIKE(hybrid.CTIDH1024X25519),
	hybrid.Scheme{
		"Kyber1024-CTIDH1024-X25519",
		adapter.FromNIKE(hybrid.CTIDH1024X25519),
		kyber1024.Scheme(),
	},
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
