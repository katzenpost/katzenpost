// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/katzenpost/hpqc/hash"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
)

func signedMix(t *testing.T, signer restoreNode, desc *pki.MixDescriptor) []byte {
	up := &pki.SignedUpload{MixDescriptor: desc}
	require.NoError(t, up.Sign(signer.priv, signer.pub))
	raw, err := up.Marshal()
	require.NoError(t, err)
	return raw
}

func signedReplica(t *testing.T, signer restoreNode, desc *pki.ReplicaDescriptor) []byte {
	up := &pki.SignedReplicaUpload{ReplicaDescriptor: desc}
	require.NoError(t, up.Sign(signer.priv, signer.pub))
	raw, err := up.Marshal()
	require.NoError(t, err)
	return raw
}

func TestRestoredDescriptorRejectsBadEntries(t *testing.T) {
	scheme := signSchemes.ByName(testSchemeName)
	epoch, _, _ := epochtime.Now()
	mix := newRestoreNode(t, scheme)
	replica := newRestoreNode(t, scheme)
	other := newRestoreNode(t, scheme)
	st := openRestoreState(t, filepath.Join(t.TempDir(), "persistence.db"), scheme.Name(), mix, replica)
	defer st.db.Close()

	mixDesc := &pki.MixDescriptor{Name: "mix1", Epoch: epoch, IdentityKey: mix.id, LinkKey: []byte("link")}
	bareMix, err := mixDesc.MarshalBinary()
	require.NoError(t, err)
	emptyMix, err := (&pki.SignedUpload{}).Marshal()
	require.NoError(t, err)
	shortMix := signedMix(t, mix, &pki.MixDescriptor{Name: "mix1", Epoch: epoch, IdentityKey: mix.id[:3], LinkKey: []byte("link")})

	repDesc := &pki.ReplicaDescriptor{Name: "replica1", ReplicaID: 1, Epoch: epoch, IdentityKey: replica.id, LinkKey: []byte("link")}
	bareRep, err := repDesc.Marshal()
	require.NoError(t, err)
	emptyRep, err := (&pki.SignedReplicaUpload{}).Marshal()
	require.NoError(t, err)
	shortRep := signedReplica(t, replica, &pki.ReplicaDescriptor{Name: "replica1", ReplicaID: 1, Epoch: epoch, IdentityKey: replica.id[:3], LinkKey: []byte("link")})

	for name, raw := range map[string][]byte{
		"garbage":     []byte("not a signed upload"),
		"legacy bare": bareMix,
		"nil desc":    emptyMix,
		"short key":   shortMix,
		"forged":      signedMix(t, other, mixDesc),
	} {
		_, err := st.restoredMixDescriptor(raw)
		require.Error(t, err, "mix "+name)
	}
	for name, raw := range map[string][]byte{
		"garbage":     []byte("not a signed upload"),
		"legacy bare": bareRep,
		"nil desc":    emptyRep,
		"short key":   shortRep,
		"forged":      signedReplica(t, other, repDesc),
	} {
		_, err := st.restoredReplicaDescriptor(raw)
		require.Error(t, err, "replica "+name)
	}

	got, err := st.restoredMixDescriptor(signedMix(t, mix, mixDesc))
	require.NoError(t, err)
	require.Equal(t, mixDesc, got)
	gotRep, err := st.restoredReplicaDescriptor(signedReplica(t, replica, repDesc))
	require.NoError(t, err)
	require.Equal(t, repDesc, gotRep)
}

func TestRestoreKeepsGoodAndDropsBadEntries(t *testing.T) {
	scheme := signSchemes.ByName(testSchemeName)
	epoch, _, _ := epochtime.Now()
	mix := newRestoreNode(t, scheme)
	replica := newRestoreNode(t, scheme)
	other := newRestoreNode(t, scheme)
	path := filepath.Join(t.TempDir(), "persistence.db")
	st := openRestoreState(t, path, scheme.Name(), mix, replica)
	require.NoError(t, st.db.Close())

	mixDesc := &pki.MixDescriptor{Name: "mix1", Epoch: epoch, IdentityKey: mix.id, LinkKey: []byte("link")}
	repDesc := &pki.ReplicaDescriptor{Name: "replica1", ReplicaID: 1, Epoch: epoch, IdentityKey: replica.id, LinkKey: []byte("link")}
	forgedMix := &pki.MixDescriptor{Name: "mix1", Epoch: epoch, IdentityKey: other.id, LinkKey: []byte("link")}
	forgedRep := &pki.ReplicaDescriptor{Name: "replica1", ReplicaID: 1, Epoch: epoch, IdentityKey: other.id, LinkKey: []byte("link")}
	mixHash := hash.Sum256(mix.id)
	repHash := hash.Sum256(replica.id)
	otherHash := hash.Sum256(other.id)
	junk := hash.Sum256([]byte("junk"))

	db, err := bolt.Open(path, 0600, nil)
	require.NoError(t, err)
	put := func(bucket string, entries map[[publicKeyHashSize]byte][]byte) {
		require.NoError(t, db.Update(func(tx *bolt.Tx) error {
			b, err := tx.Bucket([]byte(bucket)).CreateBucketIfNotExists(epochToBytes(epoch))
			if err != nil {
				return err
			}
			for k, v := range entries {
				if err := b.Put(k[:], v); err != nil {
					return err
				}
			}
			return nil
		}))
	}
	put(descriptorsBucket, map[[publicKeyHashSize]byte][]byte{
		mixHash:   signedMix(t, mix, mixDesc),
		otherHash: signedMix(t, mix, forgedMix),
		junk:      []byte("not a signed upload"),
	})
	put(replicaDescriptorsBucket, map[[publicKeyHashSize]byte][]byte{
		repHash:   signedReplica(t, replica, repDesc),
		otherHash: signedReplica(t, replica, forgedRep),
		junk:      []byte("not a signed upload"),
	})
	require.NoError(t, db.Close())

	st = openRestoreState(t, path, scheme.Name(), mix, replica)
	defer st.db.Close()
	require.Equal(t, map[[publicKeyHashSize]byte]*pki.MixDescriptor{mixHash: mixDesc}, st.descriptors[epoch])
	require.Equal(t, map[[publicKeyHashSize]byte]*pki.ReplicaDescriptor{repHash: repDesc}, st.replicaDescriptors[epoch])
}
