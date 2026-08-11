// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/katzenpost/hpqc/hash"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func TestRejectionLogCarriesLocalClock(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	states, _ := buildScenarioStates(t, 2, epoch+2, nil)
	from, to := states[0], states[1]
	p := filepath.Join(t.TempDir(), "notice.log")
	lb, err := log.New(p, "NOTICE", false)
	require.NoError(t, err)
	t.Cleanup(func() { lb.Close() })
	to.log = lb.GetLogger("to")
	to.votingEpoch = epoch + 2
	pk := hash.Sum256From(from.s.identityPublicKey)

	resp := to.onSigUpload(&commands.Sig{Epoch: epoch + 1, PublicKey: from.s.identityPublicKey}, pk[:])
	require.EqualValues(t, commands.SigTooLate, resp.(*commands.SigStatus).ErrorCode)
	resp = to.onVoteUpload(&commands.Vote{Epoch: epoch + 3, PublicKey: from.s.identityPublicKey}, pk[:])
	require.EqualValues(t, commands.VoteTooEarly, resp.(*commands.VoteStatus).ErrorCode)

	b, err := os.ReadFile(p)
	require.NoError(t, err)
	out := string(b)
	require.Regexp(t, `Signature from .* received too late: .* \(local epoch=\d+ elapsed=\S+ phase=\S+\)`, out)
	require.Regexp(t, `Vote from .* received too early: .* \(local epoch=\d+ elapsed=\S+ phase=\S+\)`, out)
}
