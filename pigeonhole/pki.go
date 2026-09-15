// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package common contains code that is useful to pigeonhole clients and Couriers.
package pigeonhole

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/rand"

	cpki "github.com/katzenpost/katzenpost/core/pki"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// CryptoRandIndex returns a uniformly-distributed int in [0, n) using
// hpqc's cryptographic Reader. Rejection sampling at the top of the
// uint64 sample space removes modulo bias, and Reader is stateless
// per-call so concurrent callers cannot race. This replaces a prior
// package-global *math/rand.Rand that was documented as not safe for
// concurrent use.
func CryptoRandIndex(n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("CryptoRandIndex: n must be > 0, got %d", n)
	}
	un := uint64(n)
	// r = 2^64 mod un. In uint64 arithmetic, (0 - un) wraps to 2^64 - un,
	// whose remainder mod un equals 2^64 mod un.
	r := (uint64(0) - un) % un
	var buf [8]byte
	for {
		if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
			return 0, err
		}
		v := binary.BigEndian.Uint64(buf[:])
		// r == 0: n divides 2^64 exactly (n is a power of two ≤ 2^64),
		// so every uint64 maps unbiased. Otherwise, reject the top r
		// values of the uint64 range to keep v % un unbiased.
		if r == 0 || v < (uint64(0)-r) {
			return int(v % un), nil
		}
	}
}

// GetRandomIntermediateReplicas returns two random replica numbers and their public keys.
func GetRandomIntermediateReplicas(doc *cpki.Document, boxid *[32]byte) ([2]uint8, []nike.PublicKey, error) {
	if doc == nil {
		return [2]uint8{}, nil, errors.New("PKI document is nil")
	}
	if doc.StorageReplicas == nil {
		return [2]uint8{}, nil, errors.New("PKI document has nil StorageReplicas")
	}

	numReplicas := uint8(len(doc.StorageReplicas))

	shards, err := replicaCommon.GetShards(boxid, doc)
	if err != nil {
		return [2]uint8{}, nil, err
	}

	// shardReplicaIDs stores the static ReplicaID values for the shards,
	// not array indices into StorageReplicas.
	// We use a slice (not fixed array) to only include shards that are actually online,
	// avoiding the bug where an uninitialized element with value 0 could incorrectly
	// exclude a replica with ReplicaID 0.
	shardReplicaIDs := make([]uint8, 0, len(shards))
	for _, shard := range shards {
		for _, replica := range doc.StorageReplicas {
			if hmac.Equal(shard.IdentityKey, replica.IdentityKey) {
				shardReplicaIDs = append(shardReplicaIDs, replica.ReplicaID)
				break
			}
		}
	}

	// Build a list of all available ReplicaIDs for random selection
	allReplicaIDs := make([]uint8, len(doc.StorageReplicas))
	for i, replica := range doc.StorageReplicas {
		allReplicaIDs[i] = replica.ReplicaID
	}

	getReplicaPubKeys := func(replica1, replica2 uint8) ([]nike.PublicKey, error) {
		replicaPubKeys := make([]nike.PublicKey, 2)
		replicaEpoch, _, _ := replicaCommon.ReplicaNow()
		for i, replicaNum := range [2]uint8{replica1, replica2} {
			desc, err := replicaCommon.ReplicaNum(replicaNum, doc)
			if err != nil {
				return nil, err
			}
			keyBytes, exists := desc.EnvelopeKeys[replicaEpoch]
			if !exists {
				return nil, fmt.Errorf("no envelope key found for replica %d at epoch %d", replicaNum, replicaEpoch)
			}
			if len(keyBytes) == 0 {
				return nil, fmt.Errorf("empty envelope key for replica %d at epoch %d", replicaNum, replicaEpoch)
			}
			replicaPubKeys[i], err = replicaCommon.NikeScheme.UnmarshalBinaryPublicKey(keyBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal key for replica %d (keySize=%d): %w", replicaNum, len(keyBytes), err)
			}
		}
		return replicaPubKeys, nil
	}

	// Helper to pick a random ReplicaID from allReplicaIDs, excluding certain IDs
	pickRandomReplicaID := func(exclude ...uint8) (uint8, error) {
		for {
			idx, err := CryptoRandIndex(len(allReplicaIDs))
			if err != nil {
				return 0, err
			}
			candidate := allReplicaIDs[idx]
			excluded := false
			for _, ex := range exclude {
				if candidate == ex {
					excluded = true
					break
				}
			}
			if !excluded {
				return candidate, nil
			}
		}
	}

	switch {
	case numReplicas < 2:
		return [2]uint8{}, nil, errors.New("insufficient storage replicas: need at least 2 replicas")
	case numReplicas == 2:
		// With only 2 replicas, use both of their ReplicaIDs
		replicaPubKeys, err := getReplicaPubKeys(allReplicaIDs[0], allReplicaIDs[1])
		if err != nil {
			return [2]uint8{}, nil, err
		}
		return [2]uint8{allReplicaIDs[0], allReplicaIDs[1]}, replicaPubKeys, nil
	case numReplicas == 3:
		// We cannot select two random replicas because we have only 3 replicas,
		// so only the second one is random.
		// If no shards are available, pick two random replicas.
		var replica1, replica2 uint8
		var err error
		if len(shardReplicaIDs) > 0 {
			replica1 = shardReplicaIDs[0]
			replica2, err = pickRandomReplicaID(replica1)
			if err != nil {
				return [2]uint8{}, nil, err
			}
		} else {
			replica1, err = pickRandomReplicaID()
			if err != nil {
				return [2]uint8{}, nil, err
			}
			replica2, err = pickRandomReplicaID(replica1)
			if err != nil {
				return [2]uint8{}, nil, err
			}
		}

		replicaPubKeys, err := getReplicaPubKeys(replica1, replica2)
		if err != nil {
			return [2]uint8{}, nil, err
		}

		return [2]uint8{replica1, replica2}, replicaPubKeys, nil
	case numReplicas >= 4:
		// Select two random replicas that are not the replicas
		// in our shardReplicaIDs. The shardReplicaIDs slice contains only
		// the ReplicaIDs of online shard replicas (may be 0, 1, or 2 elements).
		replica1, err := pickRandomReplicaID(shardReplicaIDs...)
		if err != nil {
			return [2]uint8{}, nil, err
		}
		replica2, err := pickRandomReplicaID(append([]uint8{replica1}, shardReplicaIDs...)...)
		if err != nil {
			return [2]uint8{}, nil, err
		}

		replicaPubKeys, err := getReplicaPubKeys(replica1, replica2)
		if err != nil {
			return [2]uint8{}, nil, err
		}

		return [2]uint8{replica1, replica2}, replicaPubKeys, nil
	}

	// unreachable
	panic("unreachable code path")
}
