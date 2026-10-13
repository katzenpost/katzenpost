// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
)

const goldenNoticeFreeParametersKey = "a5624d75f93400674c616d6264614cf93000674c616d6264614df92c00674c616d62646150f93800674c616d62646152f94000"

func TestVotedParametersKeyWithoutNoticeUnchanged(t *testing.T) {
	k, err := votedParametersKey(&pki.Document{Mu: 0.25, LambdaP: 0.5, LambdaL: 0.125, LambdaM: 0.0625, LambdaR: 2})
	require.NoError(t, err)
	require.Equal(t, goldenNoticeFreeParametersKey, hex.EncodeToString([]byte(k)))
}

func TestNoticeMajorityWins(t *testing.T) {
	n := config.Notice{MinClientVersion: "v0.0.105", ClientNotice: "upgrade soon"}
	docs, errs := runNoticeRound(t, []config.Notice{n, n, {ClientNotice: "misconfigured"}})
	for i := range docs {
		require.NoError(t, errs[i])
		require.Equal(t, "v0.0.105", docs[i].MinClientVersion)
		require.Equal(t, "upgrade soon", docs[i].ClientNotice)
	}
}

func TestMalformedNoticeVoteIsOutvoted(t *testing.T) {
	n := config.Notice{ClientNotice: "upgrade soon"}
	docs, errs := runNoticeRound(t, []config.Notice{n, n, {ClientNotice: strings.Repeat("n", 513)}})
	for i := range docs {
		require.NoError(t, errs[i])
		require.Equal(t, "upgrade soon", docs[i].ClientNotice)
	}
}

func TestMalformedNoticeVoteIsLogged(t *testing.T) {
	states, epoch := exchangeNoticeVotes(t, []config.Notice{
		{ClientNotice: "a"},
		{ClientNotice: "a"},
		{ClientNotice: strings.Repeat("n", 513)},
	})
	p := filepath.Join(t.TempDir(), "warning.log")
	lb, err := log.New(p, "WARNING", false)
	require.NoError(t, err)
	t.Cleanup(func() { lb.Close() })
	s := states[0]
	s.log = lb.GetLogger("notice")

	s.Lock()
	_, _, _, notice, err := s.tallyVotes(epoch)
	s.Unlock()
	require.NoError(t, err)
	require.Equal(t, "a", notice.ClientNotice)

	b, err := os.ReadFile(p)
	require.NoError(t, err)
	require.Contains(t, string(b), s.authorityName(hash.Sum256From(states[2].s.identityPublicKey)), "no warning names the authority whose vote carries a malformed notice")
}
