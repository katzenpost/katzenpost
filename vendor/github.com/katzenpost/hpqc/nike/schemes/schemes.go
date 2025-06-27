package schemes

import (
	"strings"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh1024"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh2048"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh511"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh512"
	"github.com/katzenpost/hpqc/nike/hybrid"
	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/nike/x448"
	"github.com/katzenpost/hpqc/rand"
)

var potentialSchemes = [...]nike.Scheme{

	// post quantum NIKE schemes
	ctidh511.Scheme(),
	ctidh512.Scheme(),
	ctidh1024.Scheme(),
	ctidh2048.Scheme(),

	// hybrid NIKE schemes

	// see ticket https://github.com/katzenpost/hpqc/issues/34
	//hybrid.CTIDH511X25519,

	hybrid.CTIDH512X25519,
	hybrid.CTIDH512X448,
	hybrid.CTIDH1024X25519,
	hybrid.CTIDH1024X448,
	hybrid.CTIDH2048X448,

	// NOBS CSIDH doesn't work on arm32
	// XXX TODO: deprecate and remove.
	hybrid.NOBS_CSIDH512X25519,
}

var allSchemes = []nike.Scheme{

	// classical NIKE schemes
	x25519.Scheme(rand.Reader),
	x448.Scheme(rand.Reader),

	// Classical DiffieHellman imeplementation has a bug with this ticket:
	// https://github.com/katzenpost/hpqc/issues/39
	//diffiehellman.Scheme(),
}

var allSchemeNames map[string]nike.Scheme

func init() {
	allSchemeNames = make(map[string]nike.Scheme)
	for _, scheme := range potentialSchemes {
		if scheme != nil {
			allSchemes = append(allSchemes, scheme)
		}
	}
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
