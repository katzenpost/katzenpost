package schemes

import (
	"strings"

	"github.com/katzenpost/circl/kem/frodo/frodo640shake"
	"github.com/katzenpost/circl/kem/kyber/kyber768"
	"github.com/katzenpost/circl/kem/mceliece/mceliece348864"
	"github.com/katzenpost/circl/kem/mceliece/mceliece348864f"
	"github.com/katzenpost/circl/kem/mceliece/mceliece460896"
	"github.com/katzenpost/circl/kem/mceliece/mceliece460896f"
	"github.com/katzenpost/circl/kem/mceliece/mceliece6688128"
	"github.com/katzenpost/circl/kem/mceliece/mceliece6688128f"
	"github.com/katzenpost/circl/kem/mceliece/mceliece6960119"
	"github.com/katzenpost/circl/kem/mceliece/mceliece6960119f"
	"github.com/katzenpost/circl/kem/mceliece/mceliece8192128"
	"github.com/katzenpost/circl/kem/mceliece/mceliece8192128f"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/adapter"
	"github.com/katzenpost/hpqc/kem/combiner"
	"github.com/katzenpost/hpqc/kem/hybrid"
	"github.com/katzenpost/hpqc/kem/mlkem768"
	"github.com/katzenpost/hpqc/kem/sntrup"
	"github.com/katzenpost/hpqc/kem/xwing"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh1024"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh2048"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh511"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh512"
	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/nike/x448"
	"github.com/katzenpost/hpqc/rand"
)

var potentialSchemes = [...]kem.Scheme{

	// PQ KEMs

	adapter.FromNIKE(ctidh511.Scheme()),
	adapter.FromNIKE(ctidh512.Scheme()),
	adapter.FromNIKE(ctidh1024.Scheme()),
	adapter.FromNIKE(ctidh2048.Scheme()),

	// hybrid KEMs

	combiner.New(
		"CTIDH512-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(ctidh512.Scheme()),
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
		},
	),
	combiner.New(
		"CTIDH1024-X448",
		[]kem.Scheme{
			adapter.FromNIKE(ctidh1024.Scheme()),
			adapter.FromNIKE(x448.Scheme(rand.Reader)),
		},
	),
}

var allSchemes = []kem.Scheme{

	// classical KEM schemes (converted from NIKE via hashed elgamal construction)

	// Classical DiffieHellman imeplementation has a bug with this ticket:
	// https://github.com/katzenpost/hpqc/issues/39
	//adapter.FromNIKE(diffiehellman.Scheme()),

	adapter.FromNIKE(x25519.Scheme(rand.Reader)),
	adapter.FromNIKE(x448.Scheme(rand.Reader)),

	// post quantum KEM schemes

	mlkem768.Scheme(),
	sntrup.Scheme(),
	frodo640shake.Scheme(),
	mceliece348864.Scheme(),
	mceliece348864f.Scheme(),
	mceliece460896.Scheme(),
	mceliece460896f.Scheme(),
	mceliece6688128.Scheme(),
	mceliece6688128f.Scheme(),
	mceliece6960119.Scheme(),
	mceliece6960119f.Scheme(),
	mceliece8192128.Scheme(),
	mceliece8192128f.Scheme(),

	// hybrid KEM schemes

	xwing.Scheme(),

	// XXX TODO: must soon deprecate use of "hybrid.New" in favour of "combiner.New".
	// We'd also like to remove Kyber now that we have mlkem768.
	hybrid.New(
		"Kyber768-X25519",
		adapter.FromNIKE(x25519.Scheme(rand.Reader)),
		kyber768.Scheme(),
	),

	// If Xwing is not the PQ Hybrid KEM you are looking for then we recommend
	// using our secure generic KEM combiner:
	combiner.New(
		"MLKEM768-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			mlkem768.Scheme(),
		},
	),
	combiner.New(
		"MLKEM768-X448",
		[]kem.Scheme{
			adapter.FromNIKE(x448.Scheme(rand.Reader)),
			mlkem768.Scheme(),
		},
	),

	combiner.New(
		"FrodoKEM-640-SHAKE-X448",
		[]kem.Scheme{
			adapter.FromNIKE(x448.Scheme(rand.Reader)),
			frodo640shake.Scheme(),
		},
	),
	combiner.New(
		"sntrup4591761-X448",
		[]kem.Scheme{
			adapter.FromNIKE(x448.Scheme(rand.Reader)),
			sntrup.Scheme(),
		},
	),

	// all the Classic McEliece's from our fork of circl
	combiner.New(
		"mceliece348864-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			mceliece348864.Scheme(),
		},
	),
	combiner.New(
		"mceliece348864f-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			mceliece348864f.Scheme(),
		},
	),
	combiner.New(
		"mceliece460896-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			mceliece460896.Scheme(),
		},
	),
	combiner.New(
		"mceliece460896f-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			mceliece460896f.Scheme(),
		},
	),
	combiner.New(
		"mceliece6688128-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			mceliece6688128.Scheme(),
		},
	),
	combiner.New(
		"mceliece6688128f-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			mceliece6688128f.Scheme(),
		},
	),
	combiner.New(
		"mceliece6960119-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			mceliece6960119.Scheme(),
		},
	),
	combiner.New(
		"mceliece6960119f-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			mceliece6960119f.Scheme(),
		},
	),
	combiner.New(
		"mceliece8192128-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			mceliece8192128.Scheme(),
		},
	),
	combiner.New(
		"mceliece8192128f-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			mceliece8192128f.Scheme(),
		},
	),
}

var allSchemeNames map[string]kem.Scheme

func init() {
	allSchemeNames = make(map[string]kem.Scheme)
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
func ByName(name string) kem.Scheme {
	ret := allSchemeNames[strings.ToLower(name)]
	return ret
}

// All returns all NIKE schemes supported.
func All() []kem.Scheme {
	a := allSchemes
	return a[:]
}
