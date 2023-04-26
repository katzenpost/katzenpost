package schemes

import (
	"github.com/cloudflare/circl/kem"
	"strings"

	"github.com/katzenpost/katzenpost/core/crypto/kem/adapter"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

var allSchemes = [...]kem.Scheme{
	adapter.FromNIKE(ecdh.NewEcdhNike(rand.Reader)),
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
