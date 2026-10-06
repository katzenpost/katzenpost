// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
)

func missingDocumentState(t *testing.T, elapsed time.Duration) (*state, string) {
	savedScheme := testSignatureScheme
	testSignatureScheme = signSchemes.ByName(testSchemeName)
	t.Cleanup(func() { testSignatureScheme = savedScheme })
	st, _, _ := newSingleAuthorityState(t)
	p := clockLogFile(t, st)
	savedEpoch := epochtime.Epoch
	epochtime.Epoch = time.Now().Add(-elapsed)
	t.Cleanup(func() { epochtime.Epoch = savedEpoch })
	return st, p
}

func countLines(t *testing.T, p, pattern string) int {
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	return len(regexp.MustCompile(pattern).FindAll(b, -1))
}

func TestMissingDocumentWarnsOncePerEpoch(t *testing.T) {
	st, p := missingDocumentState(t, 7*(epochtime.Period()/8)+time.Second)
	now, _, _ := epochtime.Now()
	for i := 0; i < 3; i++ {
		_, err := st.documentForEpoch(now)
		require.ErrorIs(t, err, errGone)
		_, err = st.documentForEpoch(now + 1)
		require.ErrorIs(t, err, errGone)
	}
	require.Eventually(t, func() bool {
		return countLines(t, p, `No document for current epoch`) > 0 && countLines(t, p, `No document for next epoch`) > 0
	}, 5*time.Second, 20*time.Millisecond)
	require.Equal(t, 1, countLines(t, p, `WARN.*No document for current epoch`))
	require.Equal(t, 1, countLines(t, p, `WARN.*No document for next epoch`))
	require.Equal(t, 0, countLines(t, p, `ERRO`))
}

func TestBootstrapTooLateIsAWarning(t *testing.T) {
	st, p := missingDocumentState(t, MixPublishDeadline()+time.Second)
	now, _, _ := epochtime.Now()
	st.Lock()
	st.documents = map[uint64]*pki.Document{now - 1: {}, now: {}}
	st.Unlock()
	db, err := bolt.Open(filepath.Join(t.TempDir(), "persistence.db"), 0600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	st.db = db
	require.NoError(t, st.restorePersistence())
	st.state = stateBootstrap
	st.fsm()
	require.Eventually(t, func() bool { return countLines(t, p, `Too late to vote this round`) == 1 }, 5*time.Second, 20*time.Millisecond)
	require.Equal(t, 1, countLines(t, p, `WARN.*Too late to vote this round`))
	require.Equal(t, 0, countLines(t, p, `ERRO`))
}
