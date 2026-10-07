// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
)

func TestRestoreContinuesPastBadDocument(t *testing.T) {
	scheme := signSchemes.ByName(testSchemeName)
	now, _, _ := epochtime.Now()
	mix := newRestoreNode(t, scheme)
	replica := newRestoreNode(t, scheme)
	path := filepath.Join(t.TempDir(), "persistence.db")
	st := openRestoreState(t, path, scheme.Name(), mix, replica)
	require.NoError(t, st.db.Close())

	mixHash := hash.Sum256(mix.id)
	descs := map[uint64]*pki.MixDescriptor{}
	db, err := bolt.Open(path, 0600, nil)
	require.NoError(t, err)
	require.NoError(t, db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket([]byte(documentsBucket)).Put(epochToBytes(now-1), []byte("not a document")); err != nil {
			return err
		}
		for _, e := range []uint64{now - 1, now, now + 1} {
			descs[e] = &pki.MixDescriptor{Name: "mix1", Epoch: e, IdentityKey: mix.id, LinkKey: []byte("link")}
			b, err := tx.Bucket([]byte(descriptorsBucket)).CreateBucketIfNotExists(epochToBytes(e))
			if err != nil {
				return err
			}
			if err := b.Put(mixHash[:], signedMix(t, mix, descs[e])); err != nil {
				return err
			}
		}
		return nil
	}))
	require.NoError(t, db.Close())

	lb, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	db, err = bolt.Open(path, 0600, nil)
	require.NoError(t, err)
	defer db.Close()
	st = &state{
		s:                      &Server{cfg: &config.Config{Server: &config.Server{PKISignatureScheme: scheme.Name()}}, logBackend: lb},
		log:                    lb.GetLogger("restore-test"),
		db:                     db,
		verifiers:              map[[publicKeyHashSize]byte]sign.PublicKey{hash.Sum256From(replica.pub): replica.pub},
		threshold:              1,
		documents:              make(map[uint64]*pki.Document),
		descriptors:            make(map[uint64]map[[publicKeyHashSize]byte]*pki.MixDescriptor),
		replicaDescriptors:     make(map[uint64]map[[publicKeyHashSize]byte]*pki.ReplicaDescriptor),
		authorizedMixes:        map[[publicKeyHashSize]byte]string{mixHash: "mix1"},
		authorizedGatewayNodes: make(map[[publicKeyHashSize]byte]string),
		authorizedServiceNodes: make(map[[publicKeyHashSize]byte]string),
		authorizedReplicaNodes: make(map[[publicKeyHashSize]byte]*authorizedReplicaInfo),
	}
	require.NoError(t, st.restorePersistence())
	require.Nil(t, st.documents[now-1])
	for e, d := range descs {
		require.Equal(t, map[[publicKeyHashSize]byte]*pki.MixDescriptor{mixHash: d}, st.descriptors[e], "epoch %d", e)
	}
}
