package schemes

import (
	"strings"

	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

// TODO(david): later we will add the CTIDH NIKE scheme.
var allSchemes = [...]nike.Nike{
	ecdh.NewEcdhNike(rand.Reader),
}

var allSchemeNames map[string]nike.Nike

func init() {
	allSchemeNames = make(map[string]nike.Nike)
	for _, scheme := range allSchemes {
		allSchemeNames[strings.ToLower(scheme.Name())] = scheme
	}
}

// ByName returns the NIKE scheme by string name.
func ByName(name string) nike.Nike {
	return allSchemeNames[strings.ToLower(name)]
}

// All returns all NIKE schemes supported.
func All() []nike.Nike {
	a := allSchemes
	return a[:]
}
