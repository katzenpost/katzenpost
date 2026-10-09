// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
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
