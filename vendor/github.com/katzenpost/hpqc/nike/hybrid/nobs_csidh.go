//go:build !ppc64le

package hybrid

import (
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/csidh"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
)

var NOBS_CSIDH512X25519 nike.Scheme = &Scheme{
	name:   "NOBS_CSIDH-X25519",
	first:  ecdh.Scheme(rand.Reader),
	second: csidh.NOBS_CSIDH512Scheme,
}
