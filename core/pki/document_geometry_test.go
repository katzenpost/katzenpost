// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-or-later

package pki

import (
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/schwarmco/go-cartesian-product"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"
)

func generateDescriptor(t *testing.T, pkiScheme sign.Scheme, linkScheme kem.Scheme, sphinxNikeScheme nike.Scheme, sphinxKemScheme kem.Scheme) *MixDescriptor {
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

	return &MixDescriptor{
		Name:        "fake mix node name",
		IdentityKey: idkey,
		LinkKey:     linkkey,
		MixKeys:     map[uint64][]byte{0: mixkey0, 1: mixkey1},
		Addresses:   map[string][]string{"tcp": []string{"tcp://127.0.0.1:12345"}},
	}
}

func generateReplica(t *testing.T, pkiScheme sign.Scheme, linkScheme kem.Scheme, replicaScheme nike.Scheme) *ReplicaDescriptor {
	idkey := make([]byte, pkiScheme.PublicKeySize())
	_, err := rand.Reader.Read(idkey)
	require.NoError(t, err)

	linkkey := make([]byte, linkScheme.PublicKeySize())
	_, err = rand.Reader.Read(linkkey)
	require.NoError(t, err)

	replicakey := make([]byte, replicaScheme.PublicKeySize())
	_, err = rand.Reader.Read(replicakey)
	require.NoError(t, err)

	return &ReplicaDescriptor{
		Name:        "fake replica name",
		IdentityKey: idkey,
		LinkKey:     linkkey,
		EnvelopeKey: replicakey,
		Addresses:   map[string][]string{"tcp": []string{"tcp://127.0.0.1:12345"}},
	}
}

func generateDocument(t *testing.T, pkiScheme sign.Scheme, linkScheme kem.Scheme, replicaScheme nike.Scheme, sphinxNikeScheme nike.Scheme, sphinxKemScheme kem.Scheme, numDirAuths, numMixNodes, numStorageReplicas int) *Document {
	mixNodes := make([]*MixDescriptor, numMixNodes)
	for i := 0; i < numMixNodes; i++ {
		mixNodes[i] = generateDescriptor(t, pkiScheme, linkScheme, sphinxNikeScheme, sphinxKemScheme)
	}
	topology := make([][]*MixDescriptor, 1)
	topology[0] = mixNodes
	replicas := make([]*ReplicaDescriptor, numStorageReplicas)
	for i := 0; i < numStorageReplicas; i++ {
		replicas[i] = generateReplica(t, pkiScheme, linkScheme, replicaScheme)
	}

	srv := make([]byte, 32)
	_, err := rand.Reader.Read(srv)
	require.NoError(t, err)

	geohash := srv
	oldhashes := [][]byte{srv, srv}

	return &Document{
		Topology:           topology,
		StorageReplicas:    replicas,
		SharedRandomValue:  srv,
		PriorSharedRandom:  oldhashes,
		SphinxGeometryHash: geohash,
		PKISignatureScheme: pkiScheme.Name(),
	}
}

func TestDocumentGeometryCartesianProductNIKESphinx(t *testing.T) {
	signatureScheme := []interface{}{"ed25519", "Ed25519 Sphincs+", "Ed448-Dilithium3"}
	linkScheme := []interface{}{"x25519", "Xwing"}
	replicaNikeScheme := []interface{}{"x25519", "CTIDH1024-X448"}
	sphinxNikeScheme := []interface{}{"x25519", "CTIDH1024-X448"}
	numMixes := []interface{}{5, 100, 1000, 10000}
	numReplicas := []interface{}{5, 10, 20, 100}
	numdir := []interface{}{5, 10, 20, 100}

	c1 := cartesian.Iter(signatureScheme, linkScheme, replicaNikeScheme, sphinxNikeScheme, numMixes, numReplicas, numdir)

	fmt.Printf("docSize, pkiScheme, linkScheme, replicaScheme, sphinxNikeScheme, numMixNodes, numStorageReplicas, numDirAuths\n")
	for p := range c1 {

		pkiScheme := signschemes.ByName(p[0].(string))
		linkScheme := kemschemes.ByName(p[1].(string))
		replicaScheme := nikeschemes.ByName(p[2].(string))
		sphinxNikeScheme := nikeschemes.ByName(p[3].(string))
		numMixNodes := p[4].(int)
		numStorageReplicas := p[5].(int)
		numDirAuths := p[6].(int)

		doc := generateDocument(t, pkiScheme, linkScheme, replicaScheme, sphinxNikeScheme, nil, numDirAuths, numMixNodes, numStorageReplicas)

		blob, err := cbor.Marshal(doc)
		require.NoError(t, err)

		docSize := len(blob) + (pkiScheme.SignatureSize() * numDirAuths)

		fmt.Printf("%d, %s, %s, %s, %s, %d, %d, %d\n", docSize, pkiScheme.Name(), linkScheme.Name(), replicaScheme.Name(), sphinxNikeScheme.Name(), numMixNodes, numStorageReplicas, numDirAuths)

	}
}

func TestDocumentGeometryCartesianProductKEMSphinx(t *testing.T) {
	signatureScheme := []interface{}{"ed25519", "Ed25519 Sphincs+", "Ed448-Dilithium3"}
	linkScheme := []interface{}{"x25519", "Xwing"}
	replicaNikeScheme := []interface{}{"x25519", "CTIDH1024-X448"}
	sphinxKemScheme := []interface{}{"x25519", "Xwing"}
	numMixes := []interface{}{5, 100, 1000, 10000}
	numReplicas := []interface{}{5, 10, 20, 100}
	numdir := []interface{}{5, 10, 20, 100}

	fmt.Printf("docSize, pkiScheme, linkScheme, replicaScheme, sphinxKEMScheme, numMixNodes, numStorageReplicas, numDirAuths\n")
	c := cartesian.Iter(signatureScheme, linkScheme, replicaNikeScheme, sphinxKemScheme, numMixes, numReplicas, numdir)
	for p := range c {

		pkiScheme := signschemes.ByName(p[0].(string))
		linkScheme := kemschemes.ByName(p[1].(string))
		replicaScheme := nikeschemes.ByName(p[2].(string))
		sphinxKemScheme := kemschemes.ByName(p[3].(string))
		numMixNodes := p[4].(int)
		numStorageReplicas := p[5].(int)
		numDirAuths := p[6].(int)

		doc := generateDocument(t, pkiScheme, linkScheme, replicaScheme, nil, sphinxKemScheme, numDirAuths, numMixNodes, numStorageReplicas)

		blob, err := cbor.Marshal(doc)
		require.NoError(t, err)

		docSize := len(blob) + (pkiScheme.SignatureSize() * numDirAuths)

		fmt.Printf("%d, %s, %s, %s, %s, %d, %d, %d\n", docSize, pkiScheme.Name(), linkScheme.Name(), replicaScheme.Name(), sphinxKemScheme.Name(), numMixNodes, numStorageReplicas, numDirAuths)

	}

}
