// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func TestVoteBeforeTheSignaturePhaseCountsInTheTally(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	epoch += 2
	states, _ := buildScenarioStates(t, 3, epoch, nil)
	t.Cleanup(func() {
		for _, s := range states {
			close(s.s.haltedCh)
			s.db.Close()
		}
	})
	for _, s := range states {
		s.genesisEpoch = epoch
		s.votingEpoch = epoch
		s.state = stateAcceptVote
	}
	target := states[0]
	upload := func(from *state) uint8 {
		v, err := from.getVote(epoch)
		require.NoError(t, err)
		raw, err := v.MarshalCertificate()
		require.NoError(t, err)
		pk := hash.Sum256From(from.s.identityPublicKey)
		return target.onVoteUpload(&commands.Vote{Epoch: epoch, PublicKey: from.s.identityPublicKey, Payload: raw}, pk[:]).(*commands.VoteStatus).ErrorCode
	}
	tally := func() error {
		target.Lock()
		defer target.Unlock()
		_, _, _, err := target.tallyVotes(epoch)
		return err
	}
	voted := func(from *state) bool {
		target.Lock()
		defer target.Unlock()
		_, ok := target.votes[epoch][hash.Sum256From(from.s.identityPublicKey)]
		return ok
	}

	_, err := target.getVote(epoch)
	require.NoError(t, err)
	target.state = stateAcceptCert
	require.Error(t, tally())

	require.EqualValues(t, commands.VoteOk, upload(states[1]))
	require.True(t, voted(states[1]))
	require.NoError(t, tally())

	target.state = stateAcceptSignature
	require.EqualValues(t, commands.VoteTooLate, upload(states[2]))
	require.False(t, voted(states[2]))
}
