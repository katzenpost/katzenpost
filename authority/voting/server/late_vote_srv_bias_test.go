// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func TestLateVoteSharedRandomCommitIgnoredPastCommitPhase(t *testing.T) {
	require := require.New(t)
	epoch, _, _ := epochtime.Now()
	states, _ := buildScenarioStates(t, 3, epoch+2, nil)
	epoch = epoch + 2
	byz, honest := states[0], states[1:]
	pkOf := func(s *state) [publicKeyHashSize]byte { return hash.Sum256From(s.s.identityPublicKey) }
	byzPK := pkOf(byz)

	for _, s := range states {
		s.votingEpoch, s.genesisEpoch = epoch, epoch
		s.state = stateAcceptVote
		s.commits = make(map[uint64]map[[publicKeyHashSize]byte][]byte)
		s.reveals = make(map[uint64]map[[publicKeyHashSize]byte][]byte)
	}

	votes := map[*state][]byte{}
	for _, h := range honest {
		v, err := h.getVote(epoch)
		require.NoError(err)
		raw, err := v.MarshalCertificate()
		require.NoError(err)
		votes[h] = raw
	}
	for _, from := range honest {
		fpk := pkOf(from)
		for _, to := range honest {
			if to == from {
				continue
			}
			r := to.onVoteUpload(&commands.Vote{Epoch: epoch, PublicKey: from.s.identityPublicKey, Payload: votes[from]}, fpk[:])
			require.EqualValues(commands.VoteOk, r.(*commands.VoteStatus).ErrorCode)
		}
	}

	for _, h := range honest {
		h.state = stateAcceptReveal
	}
	honestCommits := map[[publicKeyHashSize]byte][]byte{}
	honestReveals := map[[publicKeyHashSize]byte][]byte{}
	for _, from := range honest {
		fpk := pkOf(from)
		signed := from.reveal(epoch)
		honestCommits[fpk] = from.commits[epoch][fpk]
		honestReveals[fpk] = signed
		for _, to := range honest {
			if to == from {
				continue
			}
			r := to.onRevealUpload(&commands.Reveal{Epoch: epoch, PublicKey: from.s.identityPublicKey, Payload: signed}, fpk[:])
			require.EqualValues(commands.RevealOk, r.(*commands.RevealStatus).ErrorCode)
		}
	}

	byz.state = stateAcceptReveal
	voteA, err := byz.getVote(epoch)
	require.NoError(err)
	rawA, err := voteA.MarshalCertificate()
	require.NoError(err)
	commitA := byz.commits[epoch][byzPK]
	revealA := byz.reveals[epoch][byzPK]

	srB := new(pki.SharedRandom)
	cB, err := srB.Commit(epoch)
	require.NoError(err)
	commitB, err := cert.Sign(byz.s.identityPrivateKey, byz.s.identityPublicKey, cB, epoch)
	require.NoError(err)
	revealB, err := cert.Sign(byz.s.identityPrivateKey, byz.s.identityPublicKey, srB.Reveal(), epoch)
	require.NoError(err)
	docB := *voteA
	docB.Signatures = nil
	docB.SharedRandomCommit = map[[publicKeyHashSize]byte][]byte{byzPK: commitB}
	rawB, err := pki.SignDocument(byz.s.identityPrivateKey, byz.s.identityPublicKey, &docB)
	require.NoError(err)

	predict := func(commit, reveal []byte) []byte {
		cs := map[[publicKeyHashSize]byte][]byte{}
		rs := map[[publicKeyHashSize]byte][]byte{}
		for k, v := range honestCommits {
			cs[k] = v
			rs[k] = honestReveals[k]
		}
		cs[byzPK], rs[byzPK] = commit, reveal
		srv, err := byz.computeSharedRandom(epoch, cs, rs)
		require.NoError(err)
		return srv
	}
	srvA, srvB := predict(commitA, revealA), predict(commitB, revealB)
	require.False(bytes.Equal(srvA, srvB))

	chosenRaw, chosenReveal, chosenSRV, rejectedSRV := rawA, revealA, srvA, srvB
	if bytes.Compare(srvB, srvA) < 0 {
		chosenRaw, chosenReveal, chosenSRV, rejectedSRV = rawB, revealB, srvB, srvA
	}

	for _, h := range honest {
		rv := h.onVoteUpload(&commands.Vote{Epoch: epoch, PublicKey: byz.s.identityPublicKey, Payload: chosenRaw}, byzPK[:])
		require.EqualValues(commands.VoteOk, rv.(*commands.VoteStatus).ErrorCode)
		require.NotNil(h.votes[epoch][byzPK])
		_, ok := h.commits[epoch][byzPK]
		require.False(ok)
		rr := h.onRevealUpload(&commands.Reveal{Epoch: epoch, PublicKey: byz.s.identityPublicKey, Payload: chosenReveal}, byzPK[:])
		require.EqualValues(commands.RevealTooEarly, rr.(*commands.RevealStatus).ErrorCode)
	}

	for _, h := range honest {
		h.state = stateAcceptCert
	}
	certs := map[*state][]byte{}
	for _, h := range honest {
		h.Lock()
		c, err := h.getCertificate(epoch)
		h.Unlock()
		require.NoError(err)
		raw, err := c.MarshalCertificate()
		require.NoError(err)
		certs[h] = raw
	}
	for _, from := range honest {
		fpk := pkOf(from)
		for _, to := range honest {
			if to == from {
				continue
			}
			r := to.onCertUpload(&commands.Cert{Epoch: epoch, PublicKey: from.s.identityPublicKey, Payload: certs[from]}, fpk[:])
			require.EqualValues(commands.CertOk, r.(*commands.CertStatus).ErrorCode)
		}
	}
	for _, h := range honest {
		h.Lock()
		doc, err := h.getMyConsensus(epoch)
		h.Unlock()
		require.NoError(err)
		if bytes.Equal(doc.SharedRandomValue, chosenSRV) {
			t.Errorf("honest consensus SRV %x equals the attacker-selected candidate (rejected alternative was %x): SRV is biasable by a late voter",
				doc.SharedRandomValue[:8], rejectedSRV[:8])
		}
	}
}
