// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
)

func newUploadState(t *testing.T) *state {
	t.Helper()
	backend, err := log.New(filepath.Join(t.TempDir(), "test.log"), "ERROR", false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })
	db, err := bolt.Open(filepath.Join(t.TempDir(), "persistence.db"), 0600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.Update(func(tx *bolt.Tx) error {
		for _, b := range []string{descriptorsBucket, replicaDescriptorsBucket} {
			if _, err := tx.CreateBucketIfNotExists([]byte(b)); err != nil {
				return err
			}
		}
		return nil
	}))
	return &state{
		log:                backend.GetLogger("reupload"),
		db:                 db,
		documents:          make(map[uint64]*pki.Document),
		descriptors:        make(map[uint64]map[[publicKeyHashSize]byte]*pki.MixDescriptor),
		replicaDescriptors: make(map[uint64]map[[publicKeyHashSize]byte]*pki.ReplicaDescriptor),
		updateCh:           make(chan interface{}, 1),
	}
}

func TestDescriptorReupload(t *testing.T) {
	epoch, _, _ := epochtime.Now()

	for _, scheme := range []string{"Ed25519", "Ed25519 Sphincs+"} {
		t.Run(scheme, func(t *testing.T) {
			s := signschemes.ByName(scheme)
			require.NotNil(t, s)
			pub, priv, err := s.GenerateKey()
			require.NoError(t, err)
			idKey, err := pub.MarshalBinary()
			require.NoError(t, err)

			mix := func(name string) ([]byte, *pki.MixDescriptor) {
				su := &pki.SignedUpload{MixDescriptor: &pki.MixDescriptor{Name: name, Epoch: epoch, IdentityKey: idKey}}
				require.NoError(t, su.Sign(priv, pub))
				raw, err := su.Marshal()
				require.NoError(t, err)
				got := new(pki.SignedUpload)
				require.NoError(t, got.Unmarshal(raw))
				require.True(t, got.Verify(pub))
				return raw, got.MixDescriptor
			}
			replica := func(name string) ([]byte, *pki.ReplicaDescriptor) {
				su := &pki.SignedReplicaUpload{ReplicaDescriptor: &pki.ReplicaDescriptor{Name: name, Epoch: epoch, IdentityKey: idKey}}
				require.NoError(t, su.Sign(priv, pub))
				raw, err := su.Marshal()
				require.NoError(t, err)
				got := new(pki.SignedReplicaUpload)
				require.NoError(t, got.Unmarshal(raw))
				require.True(t, got.Verify(pub))
				return raw, got.ReplicaDescriptor
			}

			t.Run("mix", func(t *testing.T) {
				st := newUploadState(t)
				raw, desc := mix("mix1")
				require.NoError(t, st.onDescriptorUpload(raw, desc, epoch))
				raw, desc = mix("mix1")
				require.NoError(t, st.onDescriptorUpload(raw, desc, epoch))
				raw, desc = mix("mix2")
				require.ErrorContains(t, st.onDescriptorUpload(raw, desc, epoch), "Conflicting descriptor")
			})

			t.Run("replica", func(t *testing.T) {
				st := newUploadState(t)
				raw, desc := replica("replica1")
				require.NoError(t, st.onReplicaDescriptorUpload(raw, desc, epoch))
				raw, desc = replica("replica1")
				require.NoError(t, st.onReplicaDescriptorUpload(raw, desc, epoch))
				raw, desc = replica("replica2")
				require.ErrorContains(t, st.onReplicaDescriptorUpload(raw, desc, epoch), "Conflicting descriptor")
			})
		})
	}
}
