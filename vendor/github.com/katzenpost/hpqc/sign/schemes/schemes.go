// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package schemes

import (
	"strings"

	"github.com/katzenpost/circl/sign/ed448"
	"github.com/katzenpost/circl/sign/eddilithium2"
	"github.com/katzenpost/circl/sign/eddilithium3"

	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/hpqc/sign/ed25519"
	"github.com/katzenpost/hpqc/sign/hybrid"
	"github.com/katzenpost/hpqc/sign/sphincsplus"
)

var potentialSchemes = [...]sign.Scheme{
	// post quantum
	sphincsplus.Scheme(),

	// post quantum hybrids
	hybrid.Ed25519Sphincs,
	hybrid.Ed448Sphincs,
}

var allSchemes = []sign.Scheme{
	// classical
	ed25519.Scheme(),
	ed448.Scheme(),

	// hybrid post quantum
	eddilithium2.Scheme(),
	eddilithium3.Scheme(),
}

var allSchemeNames map[string]sign.Scheme

func init() {
	allSchemeNames = make(map[string]sign.Scheme)

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
func ByName(name string) sign.Scheme {
	ret := allSchemeNames[strings.ToLower(name)]
	return ret
}

// All returns all signature schemes supported.
func All() []sign.Scheme {
	a := allSchemes
	return a[:]
}
