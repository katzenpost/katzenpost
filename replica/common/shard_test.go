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

	orderedKeys := Shard(boxid, replicaKeys)
	for i := 0; i < len(orderedKeys); i++ {
		hash := hash.Sum256(orderedKeys[i])
		_, err := doc.GetReplicaNodeByKeyHash(&hash)
		require.NoError(t, err)
	}
}

func TestShardSimple(t *testing.T) {
	boxid1 := &[32]byte{}
	boxid2 := &[32]byte{}

	_, err := rand.Reader.Read(boxid1[:])
	require.NoError(t, err)
	_, err = rand.Reader.Read(boxid2[:])
	require.NoError(t, err)

	serverIdKeys := make([][]byte, 5)

	for i := 0; i < 5; i++ {
		serverIdKeys[i] = make([]byte, 32)
		_, err := rand.Reader.Read(serverIdKeys[i])
		require.NoError(t, err)
	}

	shards1 := Shard(boxid1, serverIdKeys)
	shards2 := Shard(boxid2, serverIdKeys)
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

/*
func TestShard2(t *testing.T) {
	numServers := 10
	keySize := 32
	keys := make([][]byte, numServers)
	for i := 0; i < numServers; i++ {
		keys[i] = make([]byte, keySize)
		_, err := rand.Reader.Read(keys[i])
		require.NoError(t, err)
	}

	boxid := &[32]byte{}
	_, err := rand.Reader.Read(boxid[:])
	require.NoError(t, err)

	shard := Shard2(boxid, keys)

	t.Log("Shard:")
	for _, s := range shard {
		t.Logf("entry: %x", s)
	}
}
*/

/*
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
*/
