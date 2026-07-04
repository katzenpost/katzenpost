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

type restoreNode struct {
	pub  sign.PublicKey
	priv sign.PrivateKey
	id   []byte
}

func newRestoreNode(t *testing.T, scheme sign.Scheme) restoreNode {
	pub, priv, err := scheme.GenerateKey()
	require.NoError(t, err)
	id, err := pub.MarshalBinary()
	require.NoError(t, err)
	return restoreNode{pub: pub, priv: priv, id: id}
}

func openRestoreState(t *testing.T, path, schemeName string, mix, replica restoreNode) *state {
	lb, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	db, err := bolt.Open(path, 0600, nil)
	require.NoError(t, err)
	st := &state{
		s:                      &Server{cfg: &config.Config{Server: &config.Server{PKISignatureScheme: schemeName}}, logBackend: lb},
		log:                    lb.GetLogger("restore-test"),
		db:                     db,
		documents:              make(map[uint64]*pki.Document),
		descriptors:            make(map[uint64]map[[publicKeyHashSize]byte]*pki.MixDescriptor),
		replicaDescriptors:     make(map[uint64]map[[publicKeyHashSize]byte]*pki.ReplicaDescriptor),
		authorizedMixes:        map[[publicKeyHashSize]byte]string{hash.Sum256(mix.id): "mix1"},
		authorizedGatewayNodes: make(map[[publicKeyHashSize]byte]string),
		authorizedServiceNodes: make(map[[publicKeyHashSize]byte]string),
		authorizedReplicaNodes: map[[publicKeyHashSize]byte]*authorizedReplicaInfo{
			hash.Sum256(replica.id): {Identifier: "replica1", ReplicaID: 1},
		},
	}
	require.NoError(t, st.restorePersistence())
	return st
}

func TestRestorePersistedDescriptors(t *testing.T) {
	for _, name := range []string{"Ed25519", testSchemeName} {
		t.Run(name, func(t *testing.T) {
			scheme := signSchemes.ByName(name)
			require.NotNil(t, scheme)
			epoch, _, _ := epochtime.Now()
			mix := newRestoreNode(t, scheme)
			replica := newRestoreNode(t, scheme)
			path := filepath.Join(t.TempDir(), "persistence.db")

			mixDesc := &pki.MixDescriptor{Name: "mix1", Epoch: epoch, IdentityKey: mix.id, LinkKey: []byte("link")}
			up := &pki.SignedUpload{MixDescriptor: mixDesc}
			require.NoError(t, up.Sign(mix.priv, mix.pub))
			rawUp, err := up.Marshal()
			require.NoError(t, err)

			repDesc := &pki.ReplicaDescriptor{Name: "replica1", ReplicaID: 1, Epoch: epoch, IdentityKey: replica.id, LinkKey: []byte("link")}
			repUp := &pki.SignedReplicaUpload{ReplicaDescriptor: repDesc}
			require.NoError(t, repUp.Sign(replica.priv, replica.pub))
			rawRepUp, err := repUp.Marshal()
			require.NoError(t, err)

			st := openRestoreState(t, path, name, mix, replica)
			require.NoError(t, st.onDescriptorUpload(rawUp, mixDesc, epoch))
			require.NoError(t, st.onReplicaDescriptorUpload(rawRepUp, repDesc, epoch))
			require.NoError(t, st.db.Close())

			st = openRestoreState(t, path, name, mix, replica)
			defer st.db.Close()
			require.Equal(t, mixDesc, st.descriptors[epoch][hash.Sum256(mix.id)])
			require.Equal(t, repDesc, st.replicaDescriptors[epoch][hash.Sum256(replica.id)])
		})
	}
}

func TestRestoreRejectsForgedDescriptors(t *testing.T) {
	scheme := signSchemes.ByName(testSchemeName)
	epoch, _, _ := epochtime.Now()
	mix := newRestoreNode(t, scheme)
	replica := newRestoreNode(t, scheme)
	other := newRestoreNode(t, scheme)
	path := filepath.Join(t.TempDir(), "persistence.db")

	mixDesc := &pki.MixDescriptor{Name: "mix1", Epoch: epoch, IdentityKey: mix.id, LinkKey: []byte("link")}
	up := &pki.SignedUpload{MixDescriptor: mixDesc}
	require.NoError(t, up.Sign(other.priv, other.pub))
	rawUp, err := up.Marshal()
	require.NoError(t, err)

	repDesc := &pki.ReplicaDescriptor{Name: "replica1", ReplicaID: 1, Epoch: epoch, IdentityKey: replica.id, LinkKey: []byte("link")}
	repUp := &pki.SignedReplicaUpload{ReplicaDescriptor: repDesc}
	require.NoError(t, repUp.Sign(other.priv, other.pub))
	rawRepUp, err := repUp.Marshal()
	require.NoError(t, err)

	st := openRestoreState(t, path, scheme.Name(), mix, replica)
	require.NoError(t, st.onDescriptorUpload(rawUp, mixDesc, epoch))
	require.NoError(t, st.onReplicaDescriptorUpload(rawRepUp, repDesc, epoch))
	require.NoError(t, st.db.Close())

	st = openRestoreState(t, path, scheme.Name(), mix, replica)
	defer st.db.Close()
	require.Empty(t, st.descriptors[epoch])
	require.Empty(t, st.replicaDescriptors[epoch])
}
