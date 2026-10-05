// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
)

func fileLogged(t *testing.T, st *state) func() string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "names.log")
	lb, err := log.New(p, "DEBUG", false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = lb.Close() })
	st.log = lb.GetLogger("names")
	return func() string {
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		return string(b)
	}
}

func namedKey(t *testing.T, st *state, name string) [publicKeyHashSize]byte {
	t.Helper()
	pub, _, err := signSchemes.ByName("Ed25519").GenerateKey()
	require.NoError(t, err)
	pk := hash.Sum256From(pub)
	if st.authorityNames == nil {
		st.authorityNames = map[[publicKeyHashSize]byte]string{}
	}
	if st.reverseHash == nil {
		st.reverseHash = map[[publicKeyHashSize]byte]sign.PublicKey{}
	}
	st.authorityNames[pk] = name
	st.reverseHash[pk] = pub
	return pk
}

func TestComputeSharedRandomLogsCommitterName(t *testing.T) {
	st := &state{threshold: 2}
	out := fileLogged(t, st)
	pk := namedKey(t, st, "auth-a")
	_, err := st.computeSharedRandom(1, map[[publicKeyHashSize]byte][]byte{pk: {1}}, nil)
	require.Error(t, err)
	require.Contains(t, out(), "from auth-a")
	require.NotContains(t, out(), fmt.Sprintf("%x", pk))
}

func TestThresholdConsensusLogsSignerName(t *testing.T) {
	st := &state{threshold: 1}
	out := fileLogged(t, st)
	pk := namedKey(t, st, "auth-a")
	st.myconsensus = map[uint64]*pki.Document{1: {}}
	st.signatures = map[uint64]map[[publicKeyHashSize]byte]*cert.Signature{1: {pk: {}}}
	st.Lock()
	_, _ = st.getThresholdConsensus(1)
	st.Unlock()
	require.Contains(t, out(), "AddSignature from auth-a")
	require.NotContains(t, out(), fmt.Sprintf("%x", pk))
}

func uploadState(t *testing.T) *state {
	t.Helper()
	db, err := bolt.Open(filepath.Join(t.TempDir(), "p.db"), 0600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.Update(func(tx *bolt.Tx) error {
		for _, b := range []string{descriptorsBucket, replicaDescriptorsBucket} {
			if _, err := tx.CreateBucket([]byte(b)); err != nil {
				return err
			}
		}
		return nil
	}))
	return &state{
		db:                 db,
		documents:          map[uint64]*pki.Document{},
		descriptors:        map[uint64]map[[publicKeyHashSize]byte]*pki.MixDescriptor{},
		replicaDescriptors: map[uint64]map[[publicKeyHashSize]byte]*pki.ReplicaDescriptor{},
	}
}

func TestDescriptorUploadLogsNodeName(t *testing.T) {
	st := uploadState(t)
	out := fileLogged(t, st)
	id := []byte("mix identity key")
	require.NoError(t, st.onDescriptorUpload([]byte{1}, &pki.MixDescriptor{Name: "mix-a", IdentityKey: id}, 1))
	require.Contains(t, out(), "Node mix-a: Successfully submitted descriptor")
	require.NotContains(t, out(), fmt.Sprintf("%x", hash.Sum256(id)))
}

func TestReplicaDescriptorUploadLogsNodeName(t *testing.T) {
	st := uploadState(t)
	out := fileLogged(t, st)
	id := []byte("replica identity key")
	require.NoError(t, st.onReplicaDescriptorUpload([]byte{1}, &pki.ReplicaDescriptor{Name: "replica-a", IdentityKey: id}, 1))
	require.Contains(t, out(), "Node replica-a: Successfully submitted replica descriptor")
	require.NotContains(t, out(), fmt.Sprintf("%x", hash.Sum256(id)))
}
