// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"path/filepath"
	"testing"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
)

type srAuth struct {
	pub  sign.PublicKey
	priv sign.PrivateKey
	id   [publicKeyHashSize]byte
}

func (a srAuth) pair(t *testing.T, epoch uint64) (commit, reveal []byte) {
	sr := new(pki.SharedRandom)
	c, err := sr.Commit(epoch)
	require.NoError(t, err)
	sc, err := cert.Sign(a.priv, a.pub, c, epoch+5)
	require.NoError(t, err)
	srv, err := cert.Sign(a.priv, a.pub, sr.Reveal(), epoch+5)
	require.NoError(t, err)
	return sc, srv
}

func newSRState(t *testing.T, epoch uint64, auths []srAuth) *state {
	backend, err := log.New(filepath.Join(t.TempDir(), "test.log"), "ERROR", false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })
	st := &state{
		log:            backend.GetLogger("verify-commits"),
		reverseHash:    map[[publicKeyHashSize]byte]sign.PublicKey{},
		authorityNames: map[[publicKeyHashSize]byte]string{},
		certificates:   map[uint64]map[[publicKeyHashSize]byte]*pki.Document{epoch: {}},
	}
	for i, a := range auths {
		st.reverseHash[a.id] = a.pub
		st.authorityNames[a.id] = string(rune('A' + i))
	}
	return st
}

func TestVerifyCommitsStaleCitationEjectsHonestAuthority(t *testing.T) {
	ss := signSchemes.ByName("Ed25519")
	epoch, _, _ := epochtime.Now()
	auths := make([]srAuth, 3)
	for i := range auths {
		pub, priv, err := ss.GenerateKey()
		require.NoError(t, err)
		auths[i] = srAuth{pub, priv, hash.Sum256From(pub)}
	}
	a, b, c := auths[0], auths[1], auths[2]
	cA, rA := a.pair(t, epoch)
	cB, rB := b.pair(t, epoch)
	cC, rC := c.pair(t, epoch)
	cCstale, rCstale := c.pair(t, epoch-1)

	honest := func() *pki.Document {
		return &pki.Document{
			SharedRandomCommit: map[[32]byte][]byte{a.id: cA, b.id: cB, c.id: cC},
			SharedRandomReveal: map[[32]byte][]byte{a.id: rA, b.id: rB, c.id: rC},
		}
	}
	st := newSRState(t, epoch, auths)
	st.certificates[epoch][a.id] = honest()
	st.certificates[epoch][c.id] = honest()
	st.certificates[epoch][b.id] = &pki.Document{
		SharedRandomCommit: map[[32]byte][]byte{a.id: cA, c.id: cCstale},
		SharedRandomReveal: map[[32]byte][]byte{a.id: rA, c.id: rCstale},
	}
	st.Lock()
	commits, reveals := st.verifyCommits(epoch)
	st.Unlock()
	_, cIn := commits[c.id]
	_, cRev := reveals[c.id]
	require.True(t, cIn && cRev, "an honest authority's current commit and reveal, present in two honest certificates, must survive a third certificate that cites its stale pair")
}

func TestVerifyCommitsOutcomeIsIndependentOfMapOrder(t *testing.T) {
	ss := signSchemes.ByName("Ed25519")
	epoch, _, _ := epochtime.Now()
	auths := make([]srAuth, 4)
	for i := range auths {
		pub, priv, err := ss.GenerateKey()
		require.NoError(t, err)
		auths[i] = srAuth{pub, priv, hash.Sum256From(pub)}
	}
	a, b, c, stranger := auths[0], auths[1], auths[2], auths[3]
	cA, rA := a.pair(t, epoch)
	cB, rB := b.pair(t, epoch)
	cC, rC := c.pair(t, epoch)
	cCstale, rCstale := c.pair(t, epoch-1)
	cX, rX := stranger.pair(t, epoch)

	seen := map[bool]int{}
	for i := 0; i < 200; i++ {
		st := newSRState(t, epoch, auths[:3])
		honest := func() *pki.Document {
			return &pki.Document{
				SharedRandomCommit: map[[32]byte][]byte{a.id: cA, b.id: cB, c.id: cC},
				SharedRandomReveal: map[[32]byte][]byte{a.id: rA, b.id: rB, c.id: rC},
			}
		}
		st.certificates[epoch][a.id] = honest()
		st.certificates[epoch][c.id] = honest()
		st.certificates[epoch][b.id] = &pki.Document{
			SharedRandomCommit: map[[32]byte][]byte{a.id: cA, c.id: cCstale, stranger.id: cX},
			SharedRandomReveal: map[[32]byte][]byte{a.id: rA, c.id: rCstale, stranger.id: rX},
		}
		st.Lock()
		commits, _ := st.verifyCommits(epoch)
		st.Unlock()
		_, cIn := commits[c.id]
		seen[cIn]++
	}
	require.Len(t, seen, 1, "the same certificates must always yield the same surviving set; observed both outcomes: %v", seen)
}
