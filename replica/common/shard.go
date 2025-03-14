// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"crypto/hmac"
	"errors"
	"slices"

	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/core/pki"
)

const (
	// K represents the number of shards per entry into the system.
	K = 2
)

func GetReplicaKeys(doc *pki.Document) ([][]byte, error) {
	if doc.StorageReplicas == nil {
		return nil, errors.New("GetReplicaKeys: doc.StorageReplicas is nil")
	}
	if len(doc.StorageReplicas) == 0 {
		return nil, errors.New("GetReplicaKeys: doc.StorageReplicas is empty")
	}
	keys := make([][]byte, len(doc.StorageReplicas))
	for i, replica := range doc.StorageReplicas {
		keys[i] = make([]byte, len(replica.IdentityKey))
		copy(keys[i], replica.IdentityKey)
	}
	return keys, nil
}

// Shard2 implements our consistent hashing scheme for the sharded pigeonhole database
// where K is fixed to 2.
// It returns the first K`th entries from our sorted list of hashes
// where each hash is the hash of the boxID concatenated with the server ID key.
func Shard2(boxID *[32]byte, serverIdKeys [][]byte) [][]byte {
	hashes := make([][32]byte, 2, 2)
	keys := make([][]byte, 2, 2)
	hashes[0] = [32]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	hashes[1] = [32]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	for _, key := range serverIdKeys {
		hash := blake2b.Sum256(append(key[:], boxID[:32]...))
		if slices.Compare(hashes[1][:], hash[:]) == -1 {
			continue // hash[:] > largest kept hashes[1]
		}
		cmpidx := (slices.Compare(hashes[0][:], hash[:]) & 2) >> 1
		hashes[1-cmpidx] = hashes[0]
		keys[1-cmpidx] = keys[0]
		hashes[cmpidx] = hash
		keys[cmpidx] = key[:]
	}
	return keys
}

type serverDesc struct {
	key  []byte
	hash *[32]byte
}

// Shard is slower than Shard2. therefore use Shard2 instead.
func Shard(boxID *[32]byte, serverIdKeys [][]byte) [][]byte {
	servers := make([]*serverDesc, 0, len(serverIdKeys))
	for _, key := range serverIdKeys {
		hash := blake2b.Sum256(append(key, boxID[:]...))
		d := &serverDesc{
			key:  key,
			hash: &hash,
		}
		servers = append(servers, d)
	}

	slices.SortFunc(servers, func(a, b *serverDesc) int {
		return slices.Compare(a.hash[:], b.hash[:])
	})

	result := make([][]byte, 0, K)
	for i := 0; i < K; i++ {
		result = append(result, servers[i].key)
	}

	return result
}

func GetShards(boxid *[32]byte, doc *pki.Document) ([]*pki.ReplicaDescriptor, error) {
	replicaKeys, err := GetReplicaKeys(doc)
	if err != nil {
		return nil, err
	}
	orderedKeys := Shard2(boxid, replicaKeys)
	shards := make([]*pki.ReplicaDescriptor, K)
	for i, key := range orderedKeys {
		hash := blake2b.Sum256(key)
		desc, err := doc.GetReplicaNodeByKeyHash(&hash)
		if err != nil {
			return nil, err
		}
		shards[i] = desc
		if i == K-1 {
			break
		}
	}
	return shards, nil
}

func GetRemoteShards(replicaIdPubKey sign.PublicKey, boxid *[32]byte, doc *pki.Document) ([]*pki.ReplicaDescriptor, error) {
	shards, err := GetShards(boxid, doc)
	if err != nil {
		return nil, err
	}
	ret := make([]*pki.ReplicaDescriptor, 0)
	for _, desc := range shards {
		idpubkey, err := replicaIdPubKey.MarshalBinary()
		if err != nil {
			panic(err)
		}
		if hmac.Equal(desc.IdentityKey, idpubkey) {
			continue
		}
		ret = append(ret, desc)
	}
	return ret, nil
}
