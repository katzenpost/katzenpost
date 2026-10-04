// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/sign"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
)

const raceUploaders = 8

func newRaceState(t *testing.T) *state {
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
		log:                backend.GetLogger("upload-race"),
		db:                 db,
		documents:          make(map[uint64]*pki.Document),
		descriptors:        make(map[uint64]map[[publicKeyHashSize]byte]*pki.MixDescriptor),
		replicaDescriptors: make(map[uint64]map[[publicKeyHashSize]byte]*pki.ReplicaDescriptor),
		updateCh:           make(chan interface{}, raceUploaders),
	}
}

func raceUpload(t *testing.T, upload func(i int) error) []error {
	start := make(chan struct{})
	errs := make([]error, raceUploaders)
	var wg sync.WaitGroup
	for i := range raceUploaders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = upload(i)
		}()
	}
	close(start)
	wg.Wait()
	accepted := 0
	for _, err := range errs {
		if err == nil {
			accepted++
			continue
		}
		require.True(t, strings.Contains(err.Error(), "Conflicting descriptor"), err.Error())
	}
	require.Equal(t, 1, accepted, "exactly one of %d different uploads must be accepted", raceUploaders)
	return errs
}

func storedUpload(t *testing.T, st *state, bucket string, epoch uint64, pk [publicKeyHashSize]byte) []byte {
	var raw []byte
	require.NoError(t, st.db.View(func(tx *bolt.Tx) error {
		eBkt := tx.Bucket([]byte(bucket)).Bucket(epochToBytes(epoch))
		require.NotNil(t, eBkt)
		raw = append([]byte{}, eBkt.Get(pk[:])...)
		return nil
	}))
	require.NotEmpty(t, raw)
	return raw
}

func TestConcurrentConflictingUploads(t *testing.T) {
	epoch, _, _ := epochtime.Now()

	for _, scheme := range []string{"Ed25519", "Ed25519 Sphincs+"} {
		t.Run(scheme, func(t *testing.T) {
			s := signschemes.ByName(scheme)
			require.NotNil(t, s)
			pub, priv, err := s.GenerateKey()
			require.NoError(t, err)
			idKey, err := pub.MarshalBinary()
			require.NoError(t, err)
			pk := hash.Sum256(idKey)

			t.Run("mix", func(t *testing.T) {
				raws, descs := signedMixes(t, priv, pub, idKey, epoch)
				for range 10 {
					st := newRaceState(t)
					raceUpload(t, func(i int) error { return st.onDescriptorUpload(raws[i], descs[i], epoch) })
					got := new(pki.SignedUpload)
					require.NoError(t, got.Unmarshal(storedUpload(t, st, descriptorsBucket, epoch, pk)))
					require.Equal(t, st.descriptors[epoch][pk].Name, got.MixDescriptor.Name)
				}
			})
			t.Run("replica", func(t *testing.T) {
				raws, descs := signedReplicas(t, priv, pub, idKey, epoch)
				for range 10 {
					st := newRaceState(t)
					raceUpload(t, func(i int) error { return st.onReplicaDescriptorUpload(raws[i], descs[i], epoch) })
					got := new(pki.SignedReplicaUpload)
					require.NoError(t, got.Unmarshal(storedUpload(t, st, replicaDescriptorsBucket, epoch, pk)))
					require.Equal(t, st.replicaDescriptors[epoch][pk].Name, got.ReplicaDescriptor.Name)
				}
			})
		})
	}
}

func signedMixes(t *testing.T, priv sign.PrivateKey, pub sign.PublicKey, idKey []byte, epoch uint64) ([][]byte, []*pki.MixDescriptor) {
	raws := make([][]byte, raceUploaders)
	descs := make([]*pki.MixDescriptor, raceUploaders)
	for i := range raceUploaders {
		su := &pki.SignedUpload{MixDescriptor: &pki.MixDescriptor{Name: fmt.Sprintf("mix%d", i), Epoch: epoch, IdentityKey: idKey}}
		require.NoError(t, su.Sign(priv, pub))
		raw, err := su.Marshal()
		require.NoError(t, err)
		got := new(pki.SignedUpload)
		require.NoError(t, got.Unmarshal(raw))
		raws[i], descs[i] = raw, got.MixDescriptor
	}
	return raws, descs
}

func signedReplicas(t *testing.T, priv sign.PrivateKey, pub sign.PublicKey, idKey []byte, epoch uint64) ([][]byte, []*pki.ReplicaDescriptor) {
	raws := make([][]byte, raceUploaders)
	descs := make([]*pki.ReplicaDescriptor, raceUploaders)
	for i := range raceUploaders {
		su := &pki.SignedReplicaUpload{ReplicaDescriptor: &pki.ReplicaDescriptor{Name: fmt.Sprintf("replica%d", i), Epoch: epoch, IdentityKey: idKey}}
		require.NoError(t, su.Sign(priv, pub))
		raw, err := su.Marshal()
		require.NoError(t, err)
		got := new(pki.SignedReplicaUpload)
		require.NoError(t, got.Unmarshal(raw))
		raws[i], descs[i] = raw, got.ReplicaDescriptor
	}
	return raws, descs
}
