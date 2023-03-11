package schemes

import (
	"strings"

	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/crypto/nike/csidh"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/nike/hybrid"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

// NOTE(david): The CTIDH schemes won't work unless you build with
// "ctidh" build tag.
var allSchemes = [...]nike.Scheme{
	csidh.CSIDHScheme,
	ecdh.NewEcdhNike(rand.Reader),
	hybrid.NOBS_CSIDHX25519,
	hybrid.CTIDHX25519,
}

var allSchemeNames map[string]nike.Scheme

func init() {
	allSchemeNames = make(map[string]nike.Scheme)
	for _, scheme := range allSchemes {
		allSchemeNames[strings.ToLower(scheme.Name())] = scheme
	}
}

// ByName returns the NIKE scheme by string name.
func ByName(name string) nike.Scheme {
	return allSchemeNames[strings.ToLower(name)]
}

// All returns all NIKE schemes supported.
func All() []nike.Scheme {
	a := allSchemes
	return a[:]
}
