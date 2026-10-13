// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/katzenpost/hpqc/hash"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
)

func TestRestoreChecksDescriptorMetadata(t *testing.T) {
	scheme := signSchemes.ByName(testSchemeName)
	require.NotNil(t, scheme)
	for _, accept := range []bool{false, true} {
		t.Run(fmt.Sprint(accept), func(t *testing.T) {
			epoch, _, _ := epochtime.Now()
			mix := newRestoreNode(t, scheme)
			replica := newRestoreNode(t, scheme)
			path := filepath.Join(t.TempDir(), "persistence.db")
			st := openRestoreState(t, path, scheme.Name(), mix, replica)

			mixDesc := &pki.MixDescriptor{
				Name:        "mix1",
				Epoch:       epoch,
				IdentityKey: mix.id,
				LinkKey:     []byte("link"),
				MixKeys:     map[uint64][]byte{epoch: {1}},
				Addresses:   map[string][]string{"tcp": {"tcp://127.0.0.1:1"}},
				ContactInfo: "ops@example.org\n",
			}
			repDesc := &pki.ReplicaDescriptor{
				Name:            "replica1",
				ReplicaID:       1,
				Epoch:           epoch,
				IdentityKey:     replica.id,
				LinkKey:         []byte("link"),
				EnvelopeKeys:    map[uint64][]byte{1: {1}},
				Addresses:       map[string][]string{"tcp": {"tcp://127.0.0.1:1"}},
				SoftwareVersion: "katzenpost\x00",
			}
			require.NoError(t, st.db.Update(func(tx *bolt.Tx) error {
				for bucket, kv := range map[string][2][]byte{
					descriptorsBucket:        {mix.id, signedMix(t, mix, mixDesc)},
					replicaDescriptorsBucket: {replica.id, signedReplica(t, replica, repDesc)},
				} {
					b, err := tx.Bucket([]byte(bucket)).CreateBucketIfNotExists(epochToBytes(epoch))
					if err != nil {
						return err
					}
					idHash := hash.Sum256(kv[0])
					if err := b.Put(idHash[:], kv[1]); err != nil {
						return err
					}
				}
				return nil
			}))

			st.s.cfg.Server.AcceptDescriptorMetadata = accept
			st.descriptors = make(map[uint64]map[[publicKeyHashSize]byte]*pki.MixDescriptor)
			st.replicaDescriptors = make(map[uint64]map[[publicKeyHashSize]byte]*pki.ReplicaDescriptor)
			require.NoError(t, st.restorePersistence())
			defer st.db.Close()

			if accept {
				require.Empty(t, st.descriptors[epoch], "restored a mix descriptor with a malformed ContactInfo")
				require.Empty(t, st.replicaDescriptors[epoch], "restored a replica descriptor with a malformed SoftwareVersion")
				return
			}
			require.Empty(t, st.descriptors[epoch][hash.Sum256(mix.id)].ContactInfo)
			require.Empty(t, st.replicaDescriptors[epoch][hash.Sum256(replica.id)].SoftwareVersion)
		})
	}
}
