// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func TestUnparsableVoteLogsParseFailure(t *testing.T) {
	st, key, votingEpoch := newSingleAuthorityState(t)
	p := filepath.Join(t.TempDir(), "vote.log")
	lb, err := log.New(p, "DEBUG", false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = lb.Close() })
	st.log = lb.GetLogger("vote")

	signed, err := cert.Sign(key.idKey, key.idPubKey, []byte("not-a-document"), votingEpoch+100)
	require.NoError(t, err)
	keyHash := hash.Sum256From(key.idPubKey)
	resp := st.onVoteUpload(&commands.Vote{Epoch: votingEpoch, PublicKey: key.idPubKey, Payload: signed}, keyHash[:])
	require.EqualValues(t, commands.VoteNotSigned, resp.(*commands.VoteStatus).ErrorCode)

	b, err := os.ReadFile(p)
	require.NoError(t, err)
	require.Contains(t, string(b), "Vote from auth0 failed to parse: ")
	require.NotContains(t, string(b), "signature verification")
}
