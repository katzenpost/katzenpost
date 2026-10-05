// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
)

func newServedDocsState(t *testing.T) (*state, uint64, uint64) {
	require := require.New(t)
	st, key, _ := newSingleAuthorityState(t)
	db, err := bolt.Open(filepath.Join(t.TempDir(), "p.db"), 0600, nil)
	require.NoError(err)
	t.Cleanup(func() { _ = db.Close() })
	st.db = db
	require.NoError(st.restorePersistence())
	now, _, _ := epochtime.Now()
	old, cur := now-10, now+1
	st.documents = map[uint64]*pki.Document{}
	st.serializedDocs = map[uint64][]byte{}
	doc := &pki.Document{Epoch: cur, GenesisEpoch: cur, PKISignatureScheme: testSignatureScheme.Name()}
	_, err = pki.SignDocument(key.idKey, key.idPubKey, doc)
	require.NoError(err)
	st.documents[cur] = doc
	st.documents[old] = doc
	st.serializedDocs[old] = []byte("old epoch consensus")
	return st, old, cur
}

func TestDocumentForEpochServesTheCachedBytes(t *testing.T) {
	require := require.New(t)
	st, old, cur := newServedDocsState(t)
	for _, e := range []uint64{old, cur} {
		first, err := st.documentForEpoch(e)
		require.NoError(err)
		again, err := st.documentForEpoch(e)
		require.NoError(err)
		require.Equal(first, again)
		require.Equal(first, st.serializedDocs[e])
	}
}

func TestDocumentForEpochServesTheCachedBytesHybridScheme(t *testing.T) {
	require := require.New(t)
	saved := testSignatureScheme
	testSignatureScheme = signSchemes.ByName(testSchemeName)
	defer func() { testSignatureScheme = saved }()

	st, old, cur := newServedDocsState(t)
	for _, e := range []uint64{old, cur} {
		first, err := st.documentForEpoch(e)
		require.NoError(err)
		again, err := st.documentForEpoch(e)
		require.NoError(err)
		require.Equal(first, again)
		require.Equal(first, st.serializedDocs[e])
	}
}

func TestDocumentForEpochStopsServingPrunedEpochs(t *testing.T) {
	require := require.New(t)
	st, old, cur := newServedDocsState(t)
	curBytes, err := st.documentForEpoch(cur)
	require.NoError(err)
	_, err = st.documentForEpoch(old)
	require.NoError(err)

	st.Lock()
	st.pruneDocuments()
	st.Unlock()

	_, err = st.documentForEpoch(old)
	require.Error(err)
	again, err := st.documentForEpoch(cur)
	require.NoError(err)
	require.Equal(curBytes, again)
}

func TestDocumentForEpochConcurrentWithPrune(t *testing.T) {
	require := require.New(t)
	st, old, cur := newServedDocsState(t)
	curBytes, err := st.documentForEpoch(cur)
	require.NoError(err)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				b, err := st.documentForEpoch(cur)
				if err != nil || string(b) != string(curBytes) {
					t.Errorf("current epoch served %d bytes, err %v", len(b), err)
					return
				}
				_, _ = st.documentForEpoch(old)
			}
		}()
	}
	for i := 0; i < 50; i++ {
		st.Lock()
		st.pruneDocuments()
		st.Unlock()
	}
	wg.Wait()
	_, err = st.documentForEpoch(old)
	require.Error(err)
}
