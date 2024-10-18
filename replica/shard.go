// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"slices"

	"golang.org/x/crypto/blake2b"
)

const (
	// K represents the number of shards per entry into the system.
	K = 2
)

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
