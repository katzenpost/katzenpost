package schemes

import (
	"strings"

	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

// TODO(david): later we will add the CTIDH NIKE scheme.
var allSchemes = [...]nike.Scheme{
	ecdh.NewEcdhNike(rand.Reader),
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
