package schemes

import (
	"fmt"
	"strings"

	"github.com/cloudflare/circl/kem"

	"github.com/cloudflare/circl/kem/kyber/kyber768"

	"github.com/katzenpost/katzenpost/core/crypto/kem/adapter"
	"github.com/katzenpost/katzenpost/core/crypto/kem/combiner"
	kemhybrid "github.com/katzenpost/katzenpost/core/crypto/kem/hybrid"
	"github.com/katzenpost/katzenpost/core/crypto/kem/sntrup"
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

	combiner.New(
		"Kyber768-X25519_combiner",
		[]kem.Scheme{
			adapter.FromNIKE(ecdh.NewEcdhNike(rand.Reader)),
			kyber768.Scheme(),
		},
	),

	kemhybrid.New(
		"sntrup4591761-X25519",
		adapter.FromNIKE(ecdh.NewEcdhNike(rand.Reader)),
		sntrup.Scheme(),
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
	ret := allSchemeNames[strings.ToLower(name)]
	if ret == nil {
		panic(fmt.Sprintf("no such name as %s\n", name))
	}
	return ret
}

// All returns all NIKE schemes supported.
func All() []kem.Scheme {
	a := allSchemes
	return a[:]
}
