// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime"
)

func TestAuthDocsCacheGainsNextDocumentInsideEarlyConnectWindow(t *testing.T) {
	const now = 1000
	p := epochtime.Period()
	f := newAuthFixture(t)
	nowEnt, _ := f.entry(t, now, 0, 0)
	nextEnt, _ := f.entry(t, now+1, 0, 1)
	f.p.docs[now] = nowEnt
	f.p.docs[now+1] = nextEnt

	setEpochClock(t, now, 5*(p/8))
	f.p.RLock()
	f.p.updateAuthDocsCache()
	f.p.RUnlock()
	docs, _, gotNow, _ := f.p.documentsForAuthentication()
	require.Equal(t, uint64(now), gotNow)
	require.NotContains(t, docs, nextEnt)

	setEpochClock(t, now, p-p/16)
	docs, nowDoc, gotNow, till := f.p.documentsForAuthentication()
	require.Equal(t, uint64(now), gotNow)
	require.Same(t, nowEnt, nowDoc)
	require.Contains(t, docs, nextEnt)
	require.Less(t, till, pkiEarlyConnectSlack())
}
