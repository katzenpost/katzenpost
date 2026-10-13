// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/quic/common"
)

var (
	unpinnedDialWarning = regexp.MustCompile(`WARN [^\n]*peer auth1: quic dial unpinned, no QUIC key hashes known`)
	unpinnedDialDebug   = regexp.MustCompile(`DEBU [^\n]*peer auth1: quic dial unpinned, no QUIC key hashes known`)
)

func TestUnpinnedAuthorityDialWarnsOnlyWhenTheConsensusWithholdsHashes(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	a := newQUICAuthorityKeys(t)
	keys, err := common.NewEpochKeys(t.TempDir(), common.CurrentEpoch)
	require.NoError(t, err)
	doc, err := generateMixnet(6, 2, epoch)
	require.NoError(t, err)
	withheld, err := multiSignTestDocument([]sign.PrivateKey{a.identityPrivateKey}, []sign.PublicKey{a.identityPublicKey}, doc)
	require.NoError(t, err)
	addr := a.serve(t, keys, withheld)

	logFile := filepath.Join(t.TempDir(), "client.log")
	c, peer := a.client(t, logFile)
	peer.Addresses = []string{addr}
	require.NoError(t, fetch(t, c, epoch))
	logged, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.Regexp(t, unpinnedDialDebug, string(logged), "a bootstrap dial with no consensus yet must log at debug")
	require.NotRegexp(t, unpinnedDialWarning, string(logged), "a bootstrap dial with no consensus yet must not warn")

	require.NoError(t, fetch(t, c, epoch))
	require.NoError(t, fetch(t, c, epoch))
	logged, err = os.ReadFile(logFile)
	require.NoError(t, err)
	require.Len(t, unpinnedDialWarning.FindAllString(string(logged), -1), 1, "a consensus without AuthorityQUICKeyHashes must warn once per epoch")
}
