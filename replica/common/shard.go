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

// GetConfiguredReplicaKeys returns the stable set of replica identity keys
// from the authority configuration. This set does NOT change when replicas go
// offline, ensuring consistent sharding.
func GetConfiguredReplicaKeys(doc *pki.Document) ([][]byte, error) {
	if doc.ConfiguredReplicaIdentityKeys == nil {
		return nil, errors.New("GetConfiguredReplicaKeys: doc.ConfiguredReplicaIdentityKeys is nil")
	}
	if len(doc.ConfiguredReplicaIdentityKeys) < K {
		return nil, errors.New("GetConfiguredReplicaKeys: insufficient configured replicas")
	}

	keys := make([][]byte, len(doc.ConfiguredReplicaIdentityKeys))
	for i, key := range doc.ConfiguredReplicaIdentityKeys {
		keys[i] = make([]byte, len(key))
		copy(keys[i], key)
	}
	return keys, nil
}

// maxHash is the maximum possible 32-byte hash value (all 0xff bytes).
var maxHash = [32]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
}

// Shard2 implements our consistent hashing scheme for the sharded pigeonhole database
// where K is fixed to 2.
// It returns the first K`th entries from our sorted list of hashes
// where each hash is the hash of the boxID concatenated with the server ID key.
func Shard2(boxID *[32]byte, serverIdKeys [][]byte) [][]byte {
	hashes := [2][32]byte{maxHash, maxHash}
	keys := [2][]byte{nil, nil}
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
	return keys[:]
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

// GetShards returns the ReplicaDescriptors for the replicas that should store data for a boxID.
// Uses the stable ConfiguredReplicaIdentityKeys for consistent sharding.
// Only returns descriptors for replicas that are currently online (present in StorageReplicas).
// The returned slice may have fewer than K elements if some shard replicas are offline.
func GetShards(boxid *[32]byte, doc *pki.Document) ([]*pki.ReplicaDescriptor, error) {
	replicaKeys, err := GetConfiguredReplicaKeys(doc)
	if err != nil {
		return nil, err
	}
	// Shard2 returns the K keys with smallest H(key || boxID)
	orderedKeys := Shard2(boxid, replicaKeys)
	shards := make([]*pki.ReplicaDescriptor, 0, K)
	for _, key := range orderedKeys {
		// Hash the identity key to look up the descriptor
		keyHash := blake2b.Sum256(key)
		desc, err := doc.GetReplicaNodeByKeyHash(&keyHash)
		if err != nil {
			// Replica is offline/not in document, skip it
			continue
		}
		shards = append(shards, desc)
	}
	if len(shards) == 0 {
		return nil, errors.New("GetShards: no shard replicas are currently online")
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
