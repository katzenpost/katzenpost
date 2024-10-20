// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"errors"
	"slices"

	"golang.org/x/crypto/blake2b"

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

type serverDesc struct {
	key  []byte
	hash *[32]byte
}

// Shard implements our consistent hashing scheme for the sharded pigeonhole database.
// It returns the first K`th entries from our sorted list of hashes
// where each hash is the hash of the boxID concatenated with the server ID key.
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

func Shard2(boxID *[32]byte, serverIdKeys [][]byte) [][]byte {
	hashes := make([][32]byte, 2, 2)
	keys := make([][]byte, 2, 2)
	hashes[0] = [32]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	hashes[1] = [32]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	for _, key := range serverIdKeys {
		hash := blake2b.Sum256(append(key[:32], boxID[:32]...))
		if slices.Compare(hashes[1][:], hash[:]) == -1 {
			continue // hash[:] > largest kept hashes[1]
		}
		cmpidx := (slices.Compare(hashes[0][:], hash[:]) & 2) >> 1
		hashes[1-cmpidx] = hashes[0]
		keys[1-cmpidx] = keys[0]
		hashes[cmpidx] = hash
		keys[cmpidx] = key
	}
	return keys
}
