// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"testing"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/stretchr/testify/require"
)

func TestVoteWellFormednessAndDeduplication(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	epoch += 2
	states, _ := buildScenarioStates(t, 4, epoch, nil)
	byz := states[0]
	target := states[1]
	_ = byz
	for _, s := range states {
		s.genesisEpoch = epoch
		s.votingEpoch = epoch
		s.state = stateAcceptVote
	}
	for i, s := range states {
		v, err := s.getVote(epoch)
		require.NoError(t, err)
		if i == 0 {
			forged := *v.GatewayNodes[0]
			forged.LinkKey = bytes.Repeat([]byte{0x42}, len(forged.LinkKey))
			v.GatewayNodes = []*pki.MixDescriptor{&forged, &forged, &forged}
			v.Signatures = nil
			_, err = pki.SignDocument(s.s.identityPrivateKey, s.s.identityPublicKey, v)
			require.NoError(t, err)
			require.Error(t, pki.IsDocumentWellFormed(v, target.getVerifiers()))
		}
		if s == target {
			continue
		}
		raw, err := v.MarshalCertificate()
		require.NoError(t, err)
		pk := hash.Sum256From(s.s.identityPublicKey)
		resp := target.onVoteUpload(&commands.Vote{Epoch: epoch, PublicKey: s.s.identityPublicKey, Payload: raw}, pk[:]).(*commands.VoteStatus)
		if i == 0 {
			// Byzantine vote with duplicate entries must be rejected as malformed
			require.EqualValues(t, commands.VoteMalformed, resp.ErrorCode)
		} else {
			require.EqualValues(t, commands.VoteOk, resp.ErrorCode)
		}
	}
	for _, s := range states {
		close(s.s.haltedCh)
		s.db.Close()
	}
}

func TestEqualRevealsDeterministicSRV(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	epoch += 2
	states, _ := buildScenarioStates(t, 7, epoch, nil)
	target := states[0]
	commits := map[[publicKeyHashSize]byte][]byte{}
	reveals := map[[publicKeyHashSize]byte][]byte{}
	shared := new(pki.SharedRandom)
	sameCommit, err := shared.Commit(epoch)
	require.NoError(t, err)
	for i, s := range states {
		sr := new(pki.SharedRandom)
		commit, err := sr.Commit(epoch)
		require.NoError(t, err)
		reveal := sr.Reveal()
		if i < 2 {
			commit = sameCommit
			reveal = shared.Reveal()
		}
		pk := hash.Sum256From(s.s.identityPublicKey)
		commits[pk], err = cert.Sign(s.s.identityPrivateKey, s.s.identityPublicKey, commit, epoch+5)
		require.NoError(t, err)
		reveals[pk], err = cert.Sign(s.s.identityPrivateKey, s.s.identityPublicKey, reveal, epoch+5)
		require.NoError(t, err)
	}
	outputs := map[string]bool{}
	for i := 0; i < 128; i++ {
		srv, err := target.computeSharedRandom(epoch, commits, reveals)
		require.NoError(t, err)
		outputs[string(srv)] = true
	}
	require.Equal(t, 1, len(outputs), "SRV must be strictly deterministic even with identical reveals")
	for _, s := range states {
		close(s.s.haltedCh)
		s.db.Close()
	}
}
