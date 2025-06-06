// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
)

func generateDescriptor(t *testing.T, pkiScheme sign.Scheme, linkScheme kem.Scheme, sphinxNikeScheme nike.Scheme, sphinxKemScheme kem.Scheme) *pki.MixDescriptor {
	idkey := make([]byte, pkiScheme.PublicKeySize())
	_, err := rand.Reader.Read(idkey)
	require.NoError(t, err)

	linkkey := make([]byte, linkScheme.PublicKeySize())
	_, err = rand.Reader.Read(linkkey)
	require.NoError(t, err)

	var mixkey0 []byte
	var mixkey1 []byte

	if sphinxNikeScheme == nil {
		mixkey0 = make([]byte, sphinxKemScheme.PublicKeySize())
		mixkey1 = make([]byte, sphinxKemScheme.PublicKeySize())
	} else {
		mixkey0 = make([]byte, sphinxNikeScheme.PublicKeySize())
		mixkey1 = make([]byte, sphinxNikeScheme.PublicKeySize())
	}

	_, err = rand.Reader.Read(mixkey0)
	require.NoError(t, err)
	_, err = rand.Reader.Read(mixkey1)
	require.NoError(t, err)

	return &pki.MixDescriptor{
		Name:        "fake mix node name",
		IdentityKey: idkey,
		LinkKey:     linkkey,
		MixKeys:     map[uint64][]byte{0: mixkey0, 1: mixkey1},
		Addresses:   map[string][]string{"tcp": []string{"tcp://127.0.0.1:12345"}},
	}
}

func generateReplica(t *testing.T, name string, pkiScheme sign.Scheme, linkScheme kem.Scheme, replicaScheme nike.Scheme) *pki.ReplicaDescriptor {
	pubkey, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)

	idkey, err := pubkey.MarshalBinary()
	require.NoError(t, err)
	_, err = rand.Reader.Read(idkey)
	require.NoError(t, err)

	linkkey := make([]byte, linkScheme.PublicKeySize())
	_, err = rand.Reader.Read(linkkey)
	require.NoError(t, err)

	replicakey := make([]byte, replicaScheme.PublicKeySize())
	_, err = rand.Reader.Read(replicakey)
	require.NoError(t, err)

	epoch, _, _ := epochtime.Now()

	return &pki.ReplicaDescriptor{
		Name:         name,
		IdentityKey:  idkey,
		LinkKey:      linkkey,
		EnvelopeKeys: map[uint64][]byte{epoch: replicakey},
		Addresses:    map[string][]string{"tcp": []string{"tcp://127.0.0.1:12345"}},
	}
}

func generateDocument(t *testing.T, pkiScheme sign.Scheme, linkScheme kem.Scheme, replicaScheme nike.Scheme, sphinxNikeScheme nike.Scheme, sphinxKemScheme kem.Scheme, numDirAuths, numMixNodes, numStorageReplicas int) *pki.Document {
	mixNodes := make([]*pki.MixDescriptor, numMixNodes)
	for i := 0; i < numMixNodes; i++ {
		mixNodes[i] = generateDescriptor(t, pkiScheme, linkScheme, sphinxNikeScheme, sphinxKemScheme)
	}
	topology := make([][]*pki.MixDescriptor, 1)
	topology[0] = mixNodes
	replicas := make([]*pki.ReplicaDescriptor, numStorageReplicas)
	for i := 0; i < numStorageReplicas; i++ {
		name := fmt.Sprintf("fake replica %d", i)
		replicas[i] = generateReplica(t, name, pkiScheme, linkScheme, replicaScheme)
	}

	srv := make([]byte, 32)
	_, err := rand.Reader.Read(srv)
	require.NoError(t, err)

	geohash := srv
	oldhashes := [][]byte{srv, srv}

	return &pki.Document{
		Topology:           topology,
		StorageReplicas:    replicas,
		SharedRandomValue:  srv,
		PriorSharedRandom:  oldhashes,
		SphinxGeometryHash: geohash,
		PKISignatureScheme: pkiScheme.Name(),
	}
}

func TestGetShards(t *testing.T) {
	numStorageReplicas := 19
	numMixNodes := 9
	numDirAuths := 9
	pkiScheme := signschemes.ByName("Ed25519 Sphincs+")
	sphinxNikeScheme := nikeschemes.ByName("x25519")
	replicaScheme := nikeschemes.ByName("x25519")
	linkScheme := kemschemes.ByName("Xwing")
	doc := generateDocument(t, pkiScheme, linkScheme, replicaScheme, sphinxNikeScheme, nil, numDirAuths, numMixNodes, numStorageReplicas)

	boxid := &[32]byte{}
	_, err := rand.Reader.Read(boxid[:])
	require.NoError(t, err)

	replicaDescs, err := GetShards(boxid, doc)
	require.NoError(t, err)
	require.Equal(t, len(replicaDescs), K)
}

func TestGetReplicaKeys(t *testing.T) {
	numStorageReplicas := 19
	numMixNodes := 9
	numDirAuths := 9
	pkiScheme := signschemes.ByName("Ed25519 Sphincs+")
	sphinxNikeScheme := nikeschemes.ByName("x25519")
	replicaScheme := nikeschemes.ByName("x25519")
	linkScheme := kemschemes.ByName("Xwing")
	doc := generateDocument(t, pkiScheme, linkScheme, replicaScheme, sphinxNikeScheme, nil, numDirAuths, numMixNodes, numStorageReplicas)
	replicaKeys, err := GetReplicaKeys(doc)
	require.NoError(t, err)
	require.Equal(t, numStorageReplicas, len(replicaKeys))

	boxid := &[32]byte{}
	_, err = rand.Reader.Read(boxid[:])
	require.NoError(t, err)

	orderedKeys := Shard2(boxid, replicaKeys)
	for i := 0; i < len(orderedKeys); i++ {
		hash := hash.Sum256(orderedKeys[i])
		_, err := doc.GetReplicaNodeByKeyHash(&hash)
		require.NoError(t, err)
	}
}

func TestShardSimple(t *testing.T) {
	// Use deterministic test data to avoid random hash collisions
	boxid1 := &[32]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}
	boxid2 := &[32]byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40}

	// Use deterministic server keys
	serverIdKeys := [][]byte{
		{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
			0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0},
		{0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
			0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0},
		{0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0,
			0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00},
		{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
			0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60},
		{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
			0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80},
	}

	shards1 := Shard2(boxid1, serverIdKeys)
	shards2 := Shard2(boxid2, serverIdKeys)

	// Verify that both calls return exactly 2 shards (K=2)
	require.Equal(t, 2, len(shards1))
	require.Equal(t, 2, len(shards2))

	// Verify that different box IDs produce different shard selections
	require.NotEqual(t, shards1, shards2)
}

func TestGetRemoteShards(t *testing.T) {
	numStorageReplicas := 19
	numMixNodes := 9
	numDirAuths := 9
	pkiScheme := signschemes.ByName("Ed25519 Sphincs+")
	sphinxNikeScheme := nikeschemes.ByName("x25519")
	replicaScheme := nikeschemes.ByName("x25519")
	linkScheme := kemschemes.ByName("Xwing")
	doc := generateDocument(t, pkiScheme, linkScheme, replicaScheme, sphinxNikeScheme, nil, numDirAuths, numMixNodes, numStorageReplicas)

	boxid := &[32]byte{}
	_, err := rand.Reader.Read(boxid[:])
	require.NoError(t, err)

	replicaDescs, err := GetShards(boxid, doc)
	require.NoError(t, err)
	replicaIdPubKey, err := pkiScheme.UnmarshalBinaryPublicKey(replicaDescs[0].IdentityKey)
	require.NoError(t, err)
	replicas, err := GetRemoteShards(replicaIdPubKey, boxid, doc)
	require.NoError(t, err)
	require.Equal(t, 1, len(replicas))

	pubkey, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)

	replicas2, err := GetRemoteShards(pubkey, boxid, doc)
	require.NoError(t, err)
	require.Equal(t, 2, len(replicas2))
}

func TestReplicaSort(t *testing.T) {
	numStorageReplicas := 19
	numMixNodes := 9
	numDirAuths := 9
	pkiScheme := signschemes.ByName("Ed25519 Sphincs+")
	sphinxNikeScheme := nikeschemes.ByName("x25519")
	replicaScheme := nikeschemes.ByName("x25519")
	linkScheme := kemschemes.ByName("Xwing")
	doc := generateDocument(t, pkiScheme, linkScheme, replicaScheme, sphinxNikeScheme, nil, numDirAuths, numMixNodes, numStorageReplicas)

	replicas, err := ReplicaSort(doc)
	require.NoError(t, err)

	require.Equal(t, len(replicas), numStorageReplicas)
}

func TestReplicaNum(t *testing.T) {
	numStorageReplicas := 19
	numMixNodes := 9
	numDirAuths := 9
	pkiScheme := signschemes.ByName("Ed25519 Sphincs+")
	sphinxNikeScheme := nikeschemes.ByName("x25519")
	replicaScheme := nikeschemes.ByName("x25519")
	linkScheme := kemschemes.ByName("Xwing")
	doc := generateDocument(t, pkiScheme, linkScheme, replicaScheme, sphinxNikeScheme, nil, numDirAuths, numMixNodes, numStorageReplicas)

	_, err := ReplicaNum(uint8(numStorageReplicas-1), doc)
	require.NoError(t, err)

	_, err = ReplicaNum(uint8(numStorageReplicas), doc)
	require.Error(t, err)
}

func BenchmarkShard2(b *testing.B) {
	numServers := 10
	keySize := 32
	keys := make([][]byte, numServers)
	for i := 0; i < numServers; i++ {
		keys[i] = make([]byte, keySize)
		_, err := rand.Reader.Read(keys[i])
		require.NoError(b, err)
	}

	boxid := &[32]byte{}
	_, err := rand.Reader.Read(boxid[:])
	require.NoError(b, err)

	var shard [][]byte
	var shard2 [][]byte
	for i := 0; i < b.N; i++ {
		shard = Shard2(boxid, keys)
	}

	shard2 = shard
	shard = shard2
}
