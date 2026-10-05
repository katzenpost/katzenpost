// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/sign"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

const internalErrorCode = 4

type uploadFixture struct {
	srv     *Server
	logPath string
	idHash  [publicKeyHashSize]byte
	pub     sign.PublicKey
	priv    sign.PrivateKey
	epoch   uint64
}

func newUploadFixture(t *testing.T, scheme string) *uploadFixture {
	t.Helper()
	s := signschemes.ByName(scheme)
	require.NotNil(t, s)
	pub, priv, err := s.GenerateKey()
	require.NoError(t, err)
	idKey, err := pub.MarshalBinary()
	require.NoError(t, err)
	idHash := hash.Sum256(idKey)

	logPath := filepath.Join(t.TempDir(), "test.log")
	backend, err := log.New(logPath, "DEBUG", false)
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
	srv := &Server{
		cfg:        &config.Config{Server: &config.Server{PKISignatureScheme: scheme}},
		state:      st,
		log:        backend.GetLogger("server"),
		fatalErrCh: make(chan error, 16),
	}
	st.s = srv
	epoch, _, _ := epochtime.Now()
	return &uploadFixture{srv: srv, logPath: logPath, idHash: idHash, pub: pub, priv: priv, epoch: epoch}
}

func (f *uploadFixture) postMix(t *testing.T, port string) uint8 {
	t.Helper()
	idKey, err := f.pub.MarshalBinary()
	require.NoError(t, err)
	up := &pki.SignedUpload{MixDescriptor: &pki.MixDescriptor{
		Name:        "mix1",
		Epoch:       f.epoch,
		IdentityKey: idKey,
		LinkKey:     []byte{1},
		MixKeys:     map[uint64][]byte{f.epoch: {1}},
		Addresses:   map[string][]string{"tcp": {"tcp://127.0.0.1:" + port}},
	}}
	require.NoError(t, up.Sign(f.priv, f.pub))
	raw, err := up.Marshal()
	require.NoError(t, err)
	resp, ok := f.srv.onPostDescriptor("peer", &commands.PostDescriptor{Epoch: f.epoch, Payload: raw}, f.idHash[:]).(*commands.PostDescriptorStatus)
	require.True(t, ok)
	return resp.ErrorCode
}

func (f *uploadFixture) postReplica(t *testing.T, port string) uint8 {
	t.Helper()
	idKey, err := f.pub.MarshalBinary()
	require.NoError(t, err)
	up := &pki.SignedReplicaUpload{ReplicaDescriptor: &pki.ReplicaDescriptor{
		Name:         "replica1",
		ReplicaID:    1,
		Epoch:        f.epoch,
		IdentityKey:  idKey,
		LinkKey:      []byte{1},
		EnvelopeKeys: map[uint64][]byte{1: {1}},
		Addresses:    map[string][]string{"tcp": {"tcp://127.0.0.1:" + port}},
	}}
	require.NoError(t, up.Sign(f.priv, f.pub))
	raw, err := up.Marshal()
	require.NoError(t, err)
	resp, ok := f.srv.onPostReplicaDescriptor("peer", &commands.PostReplicaDescriptor{Epoch: f.epoch, Payload: raw}, f.idHash[:]).(*commands.PostReplicaDescriptorStatus)
	require.True(t, ok)
	return resp.ErrorCode
}

func (f *uploadFixture) logText(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(f.logPath)
	require.NoError(t, err)
	return string(b)
}

func TestUploadInternalErrorIsNotAConflict(t *testing.T) {
	for _, scheme := range []string{"Ed25519", testSchemeName} {
		t.Run(scheme, func(t *testing.T) {
			for _, kind := range []string{"mix", "replica"} {
				t.Run(kind, func(t *testing.T) {
					f := newUploadFixture(t, scheme)
					post := f.postMix
					name := "mix1"
					if kind == "replica" {
						post, name = f.postReplica, "replica1"
					}
					require.NoError(t, f.srv.state.db.Close())
					require.Equal(t, uint8(internalErrorCode), post(t, "1"))
					text := f.logText(t)
					require.Contains(t, text, "ERRO")
					require.Contains(t, text, "internal error")
					require.Contains(t, text, name)
				})
			}
		})
	}
}

func TestUploadConflictsStayConflicts(t *testing.T) {
	for _, kind := range []string{"mix", "replica"} {
		t.Run(kind+"/changed descriptor", func(t *testing.T) {
			f := newUploadFixture(t, "Ed25519")
			post := f.postMix
			if kind == "replica" {
				post = f.postReplica
			}
			require.Equal(t, uint8(commands.DescriptorOk), post(t, "1"))
			require.Equal(t, uint8(commands.DescriptorConflict), post(t, "2"))
		})
		t.Run(kind+"/late upload", func(t *testing.T) {
			f := newUploadFixture(t, "Ed25519")
			post := f.postMix
			if kind == "replica" {
				post = f.postReplica
			}
			f.srv.state.documents[f.epoch] = &pki.Document{}
			require.Equal(t, uint8(commands.DescriptorConflict), post(t, "1"))
		})
	}
}
