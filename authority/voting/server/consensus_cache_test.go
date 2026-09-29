// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/core/pki"
)

// TestGetThresholdConsensusCachesSerializedDoc asserts that when consensus is
// formed the marshaled bytes are stored in the serializedDocs cache, so the
// first GetConsensus serves them without marshaling the document a second time.
// getThresholdConsensus already marshals the fully-signed document (to verify
// the threshold); before the fix it discarded those bytes, leaving the cache
// empty until documentForEpoch re-marshaled on the first request.
func TestGetThresholdConsensusCachesSerializedDoc(t *testing.T) {
	require := require.New(t)

	st, key, votingEpoch := newSingleAuthorityState(t)
	pk := hash.Sum256From(key.idPubKey)
	st.verifiers = map[[publicKeyHashSize]byte]sign.PublicKey{pk: key.idPubKey}
	st.threshold = 1
	st.reverseHash = map[[publicKeyHashSize]byte]sign.PublicKey{pk: key.idPubKey}
	st.documents = map[uint64]*pki.Document{}
	st.serializedDocs = map[uint64][]byte{}

	db, err := bolt.Open(filepath.Join(t.TempDir(), "p.db"), 0600, nil)
	require.NoError(err)
	t.Cleanup(func() { _ = db.Close() })
	st.db = db
	require.NoError(st.restorePersistence())

	// Our own signed view of the consensus, as getMyConsensus would have left it.
	doc := &pki.Document{
		Epoch:              votingEpoch,
		GenesisEpoch:       votingEpoch,
		PKISignatureScheme: testSignatureScheme.Name(),
	}
	_, err = pki.SignDocument(key.idKey, key.idPubKey, doc)
	require.NoError(err)
	st.myconsensus = map[uint64]*pki.Document{votingEpoch: doc}

	st.Lock()
	result, err := st.getThresholdConsensus(votingEpoch)
	st.Unlock()
	require.NoError(err)
	require.NotNil(result)

	// The cache must already hold the marshaled consensus, before any
	// GetConsensus request triggers a (second) marshal in documentForEpoch.
	cached, ok := st.serializedDocs[votingEpoch]
	require.True(ok, "getThresholdConsensus must cache the marshaled consensus")
	require.NotEmpty(cached)

	served, err := st.documentForEpoch(votingEpoch)
	require.NoError(err)
	require.Equal(cached, served, "the cached bytes must be exactly what GetConsensus serves")
}
