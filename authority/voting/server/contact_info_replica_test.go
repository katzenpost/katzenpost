// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/katzenpost/hpqc/hash"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func contactInfoReplicaServer(t *testing.T, scheme string, idHash [publicKeyHashSize]byte) *Server {
	t.Helper()
	backend, err := log.New(filepath.Join(t.TempDir(), "test.log"), "ERROR", false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })
	db, err := bolt.Open(filepath.Join(t.TempDir(), "persistence.db"), 0600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(replicaDescriptorsBucket))
		return err
	}))
	st := &state{
		log:                    backend.GetLogger("state"),
		db:                     db,
		documents:              make(map[uint64]*pki.Document),
		replicaDescriptors:     make(map[uint64]map[[publicKeyHashSize]byte]*pki.ReplicaDescriptor),
		authorizedReplicaNodes: map[[publicKeyHashSize]byte]*authorizedReplicaInfo{idHash: {Identifier: "replica1", ReplicaID: 1}},
		updateCh:               make(chan interface{}, 16),
	}
	return &Server{
		cfg:   &config.Config{Server: &config.Server{PKISignatureScheme: scheme}},
		state: st,
		log:   backend.GetLogger("server"),
	}
}

func TestUploadReplicaContactInfo(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	cases := []struct {
		contact string
		want    uint8
	}{
		{"", commands.DescriptorOk},
		{"ops@example.org", commands.DescriptorOk},
		{strings.Repeat("x", 257), commands.DescriptorInvalid},
		{"ops@example.org\n", commands.DescriptorInvalid},
	}
	for _, scheme := range []string{"Ed25519", testSchemeName} {
		s := signschemes.ByName(scheme)
		require.NotNil(t, s)
		for _, c := range cases {
			t.Run(scheme+"/"+c.contact, func(t *testing.T) {
				pub, priv, err := s.GenerateKey()
				require.NoError(t, err)
				idKey, err := pub.MarshalBinary()
				require.NoError(t, err)
				idHash := hash.Sum256(idKey)
				up := &pki.SignedReplicaUpload{ReplicaDescriptor: &pki.ReplicaDescriptor{
					Name:         "replica1",
					ReplicaID:    1,
					Epoch:        epoch,
					IdentityKey:  idKey,
					LinkKey:      []byte{1},
					EnvelopeKeys: map[uint64][]byte{1: {1}},
					Addresses:    map[string][]string{"tcp": {"tcp://127.0.0.1:1"}},
					ContactInfo:  c.contact,
				}}
				require.NoError(t, up.Sign(priv, pub))
				raw, err := up.Marshal()
				require.NoError(t, err)
				srv := contactInfoReplicaServer(t, scheme, idHash)
				resp, ok := srv.onPostReplicaDescriptor("peer", &commands.PostReplicaDescriptor{Epoch: epoch, Payload: raw}, idHash[:]).(*commands.PostReplicaDescriptorStatus)
				require.True(t, ok)
				require.Equal(t, c.want, resp.ErrorCode)
			})
		}
	}
}
