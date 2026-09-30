// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/katzenpost/hpqc/hash"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func TestOneByzantineAuthorityCannotStallOrFork(t *testing.T) {
	require := require.New(t)
	epoch, _, _ := epochtime.Now()
	states, _ := buildScenarioStates(t, 5, epoch+2, nil)
	epoch = epoch + 2
	byz, honest := states[0], states[1:]
	pkOf := func(s *state) [publicKeyHashSize]byte { return hash.Sum256From(s.s.identityPublicKey) }
	code := func(resp commands.Command) uint8 {
		switch r := resp.(type) {
		case *commands.VoteStatus:
			return r.ErrorCode
		case *commands.RevealStatus:
			return r.ErrorCode
		case *commands.CertStatus:
			return r.ErrorCode
		case *commands.SigStatus:
			return r.ErrorCode
		}
		t.Fatalf("unexpected response %T", resp)
		return 0
	}
	resign := func(s *state, d pki.Document) []byte {
		d.Signatures = nil
		raw, err := pki.SignDocument(s.s.identityPrivateKey, s.s.identityPublicKey, &d)
		require.NoError(err)
		return raw
	}

	for _, s := range states {
		s.votingEpoch, s.genesisEpoch = epoch, epoch
		s.state = stateAcceptVote
	}
	votes := map[*state][]byte{}
	for _, s := range states {
		v, err := s.getVote(epoch)
		require.NoError(err)
		raw, err := v.MarshalCertificate()
		require.NoError(err)
		votes[s] = raw
	}
	byzVote, err := pki.ParseDocument(votes[byz])
	require.NoError(err)
	other := *byzVote
	other.Mu = 0.5
	byzVoteB := resign(byz, other)
	pk := pkOf(byz)
	for i, h := range honest {
		payload := votes[byz]
		if i >= 2 {
			payload = byzVoteB
		}
		require.EqualValues(commands.VoteOk, code(h.onVoteUpload(&commands.Vote{Epoch: epoch, PublicKey: byz.s.identityPublicKey, Payload: payload}, pk[:])))
	}
	for _, from := range honest {
		fpk := pkOf(from)
		for _, to := range states {
			if to == from {
				continue
			}
			require.EqualValues(commands.VoteOk, code(to.onVoteUpload(&commands.Vote{Epoch: epoch, PublicKey: from.s.identityPublicKey, Payload: votes[from]}, fpk[:])))
		}
	}

	for _, s := range states {
		s.state = stateAcceptReveal
	}
	for _, from := range honest {
		fpk := pkOf(from)
		signed := from.reveal(epoch)
		for _, to := range states {
			if to == from {
				continue
			}
			require.EqualValues(commands.RevealOk, code(to.onRevealUpload(&commands.Reveal{Epoch: epoch, PublicKey: from.s.identityPublicKey, Payload: signed}, fpk[:])))
		}
	}

	for _, s := range states {
		s.state = stateAcceptCert
	}
	byz.Lock()
	byzCert, err := byz.getCertificate(epoch)
	byz.Unlock()
	require.NoError(err)
	target := honest[0]
	require.EqualValues(commands.CertNotSigned, code(target.onCertUpload(&commands.Cert{Epoch: epoch, PublicKey: byz.s.identityPublicKey, Payload: votes[byz]}, pk[:])), "a vote replayed as a certificate")
	replay := *byzCert
	replay.Epoch = epoch - 1
	require.EqualValues(commands.CertTooLate, code(target.onCertUpload(&commands.Cert{Epoch: epoch - 1, PublicKey: byz.s.identityPublicKey, Payload: resign(byz, replay)}, pk[:])), "a prior-epoch certificate")
	require.EqualValues(commands.CertNotSigned, code(target.onCertUpload(&commands.Cert{Epoch: epoch, PublicKey: byz.s.identityPublicKey, Payload: resign(byz, replay)}, pk[:])), "a prior-epoch document under the current command epoch")
	victim := honest[1]
	vpk := pkOf(victim)
	staleSR := new(pki.SharedRandom)
	staleCommit, err := staleSR.Commit(epoch - 1)
	require.NoError(err)
	signedStaleCommit, err := cert.Sign(victim.s.identityPrivateKey, victim.s.identityPublicKey, staleCommit, epoch+5)
	require.NoError(err)
	signedStaleReveal, err := cert.Sign(victim.s.identityPrivateKey, victim.s.identityPublicKey, staleSR.Reveal(), epoch+5)
	require.NoError(err)
	stale := *byzCert
	stale.SharedRandomCommit = map[[publicKeyHashSize]byte][]byte{}
	stale.SharedRandomReveal = map[[publicKeyHashSize]byte][]byte{}
	for k, v := range byzCert.SharedRandomCommit {
		stale.SharedRandomCommit[k] = v
		stale.SharedRandomReveal[k] = byzCert.SharedRandomReveal[k]
	}
	stale.SharedRandomCommit[vpk], stale.SharedRandomReveal[vpk] = signedStaleCommit, signedStaleReveal
	require.EqualValues(commands.CertNotSigned, code(target.onCertUpload(&commands.Cert{Epoch: epoch, PublicKey: byz.s.identityPublicKey, Payload: resign(byz, stale)}, pk[:])), "a certificate citing an honest authority's stale pair")
	require.Empty(target.certificates[epoch][pk], "no byzantine certificate may be stored")

	for _, from := range honest {
		fpk := pkOf(from)
		from.Lock()
		c, err := from.getCertificate(epoch)
		from.Unlock()
		require.NoError(err)
		require.Len(c.SharedRandomReveal, len(honest), "the byzantine commit without a reveal is dropped")
		raw, err := c.MarshalCertificate()
		require.NoError(err)
		for _, to := range honest {
			if to == from {
				continue
			}
			require.EqualValues(commands.CertOk, code(to.onCertUpload(&commands.Cert{Epoch: epoch, PublicKey: from.s.identityPublicKey, Payload: raw}, fpk[:])))
		}
	}

	for _, s := range honest {
		s.Lock()
		_, err := s.getMyConsensus(epoch)
		s.Unlock()
		require.NoError(err)
		s.state = stateAcceptSignature
	}
	for _, from := range honest {
		fpk := pkOf(from)
		sig, ok := from.myconsensus[epoch].Signatures[fpk]
		require.True(ok)
		serialized, err := sig.Marshal()
		require.NoError(err)
		signed, err := cert.Sign(from.s.identityPrivateKey, from.s.identityPublicKey, serialized, epoch)
		require.NoError(err)
		for _, to := range honest {
			if to == from {
				continue
			}
			require.EqualValues(commands.SigOk, code(to.onSigUpload(&commands.Sig{Epoch: epoch, PublicKey: from.s.identityPublicKey, Payload: signed}, fpk[:])))
		}
	}

	var first *pki.Document
	for _, s := range honest {
		s.Lock()
		doc, err := s.getThresholdConsensus(epoch)
		s.Unlock()
		require.NoError(err, "an honest authority failed to reach consensus")
		require.Equal(0.001, doc.Mu, "the equivocated parameter set must not win")
		if first == nil {
			first = doc
			continue
		}
		require.Equal(first.Sum256(), doc.Sum256(), "honest authorities forked")
		require.Equal(first.SharedRandomValue, doc.SharedRandomValue)
	}
}
