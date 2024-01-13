package schemes

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cloudflare/circl/kem"

	"github.com/cloudflare/circl/kem/kyber/kyber768"

	"github.com/katzenpost/katzenpost/core/crypto/kem/adapter"
	"github.com/katzenpost/katzenpost/core/crypto/kem/combiner"
	"github.com/katzenpost/katzenpost/core/crypto/kem/sntrup"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ctidh1024"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

var someSchemes = [...]kem.Scheme{
	adapter.FromNIKE(ecdh.NewEcdhNike(rand.Reader)),
	combiner.New(
		"Kyber768-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(ecdh.NewEcdhNike(rand.Reader)),
			kyber768.Scheme(),
		},
	),

	combiner.New(
		"sntrup4591761-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(ecdh.NewEcdhNike(rand.Reader)),
			sntrup.Scheme(),
		},
	),

	combiner.New(
		"Kyber768-sntrup4591761-X25519",
		[]kem.Scheme{
			kyber768.Scheme(),
			sntrup.Scheme(),
			adapter.FromNIKE(ecdh.NewEcdhNike(rand.Reader)),
		},
	),

	combiner.New(
		"CTIDH1024-Kyber768-sntrup4591761-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(ctidh1024.CTIDH1024Scheme),
			kyber768.Scheme(),
			sntrup.Scheme(),
			adapter.FromNIKE(ecdh.NewEcdhNike(rand.Reader)),
		},
	),
}

var allSchemeNames map[string]kem.Scheme

func init() {
	allSchemeNames = make(map[string]kem.Scheme)
	for _, scheme := range someSchemes {
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
func All() map[string]kem.Scheme {
	a := allSchemeNames
	return a
}

// Register stores the given KEM scheme under the given name.
func Register(scheme kem.Scheme) error {
	_, ok := allSchemeNames[scheme.Name()]
	if ok {
		return errors.New("already registered")
	}
	allSchemeNames[scheme.Name()] = scheme
	return nil
}
