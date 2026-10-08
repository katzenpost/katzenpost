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

func softwareVersionServer(t *testing.T, scheme string, idHash [publicKeyHashSize]byte) *Server {
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
	st := &state{
		log:                    backend.GetLogger("state"),
		db:                     db,
		documents:              make(map[uint64]*pki.Document),
		descriptors:            make(map[uint64]map[[publicKeyHashSize]byte]*pki.MixDescriptor),
		replicaDescriptors:     make(map[uint64]map[[publicKeyHashSize]byte]*pki.ReplicaDescriptor),
		authorizedMixes:        map[[publicKeyHashSize]byte]string{idHash: "mix1"},
		authorizedReplicaNodes: map[[publicKeyHashSize]byte]*authorizedReplicaInfo{idHash: {Identifier: "replica1", ReplicaID: 1}},
		updateCh:               make(chan interface{}, 16),
	}
	return &Server{
		cfg:   &config.Config{Server: &config.Server{PKISignatureScheme: scheme}},
		state: st,
		log:   backend.GetLogger("server"),
	}
}

func TestUploadSoftwareVersion(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	cases := []struct {
		version string
		want    uint8
	}{
		{"", commands.DescriptorOk},
		{"v0.0.73", commands.DescriptorOk},
		{strings.Repeat("x", 129), commands.DescriptorInvalid},
		{"v0.0.73\n", commands.DescriptorInvalid},
	}
	for _, scheme := range []string{"Ed25519", testSchemeName} {
		s := signschemes.ByName(scheme)
		require.NotNil(t, s)
		for _, c := range cases {
			t.Run(scheme+"/"+c.version, func(t *testing.T) {
				pub, priv, err := s.GenerateKey()
				require.NoError(t, err)
				idKey, err := pub.MarshalBinary()
				require.NoError(t, err)
				idHash := hash.Sum256(idKey)
				addrs := map[string][]string{"tcp": {"tcp://127.0.0.1:1"}}

				mix := &pki.SignedUpload{MixDescriptor: &pki.MixDescriptor{
					Name:            "mix1",
					Epoch:           epoch,
					IdentityKey:     idKey,
					LinkKey:         []byte{1},
					MixKeys:         map[uint64][]byte{epoch: {1}},
					Addresses:       addrs,
					SoftwareVersion: c.version,
				}}
				require.NoError(t, mix.Sign(priv, pub))
				raw, err := mix.Marshal()
				require.NoError(t, err)
				srv := softwareVersionServer(t, scheme, idHash)
				resp, ok := srv.onPostDescriptor("peer", &commands.PostDescriptor{Epoch: epoch, Payload: raw}, idHash[:]).(*commands.PostDescriptorStatus)
				require.True(t, ok)
				require.Equal(t, c.want, resp.ErrorCode)

				replica := &pki.SignedReplicaUpload{ReplicaDescriptor: &pki.ReplicaDescriptor{
					Name:            "replica1",
					ReplicaID:       1,
					Epoch:           epoch,
					IdentityKey:     idKey,
					LinkKey:         []byte{1},
					EnvelopeKeys:    map[uint64][]byte{1: {1}},
					Addresses:       addrs,
					SoftwareVersion: c.version,
				}}
				require.NoError(t, replica.Sign(priv, pub))
				raw, err = replica.Marshal()
				require.NoError(t, err)
				srv = softwareVersionServer(t, scheme, idHash)
				rresp, ok := srv.onPostReplicaDescriptor("peer", &commands.PostReplicaDescriptor{Epoch: epoch, Payload: raw}, idHash[:]).(*commands.PostReplicaDescriptorStatus)
				require.True(t, ok)
				require.Equal(t, c.want, rresp.ErrorCode)
			})
		}
	}
}
