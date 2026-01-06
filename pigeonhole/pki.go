// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package common contains code that is useful to pigeonhole clients and Couriers.
package pigeonhole

import (
	"crypto/hmac"
	"errors"
	"fmt"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/rand"

	cpki "github.com/katzenpost/katzenpost/core/pki"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

var (
	secureRand = rand.NewMath()
)

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
	// not array indices into StorageReplicas
	shardReplicaIDs := make([]uint8, 2)
	for i, shard := range shards {
		for _, replica := range doc.StorageReplicas {
			if hmac.Equal(shard.IdentityKey, replica.IdentityKey) {
				shardReplicaIDs[i] = replica.ReplicaID
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
	pickRandomReplicaID := func(exclude ...uint8) uint8 {
		for {
			idx := secureRand.Intn(len(allReplicaIDs))
			candidate := allReplicaIDs[idx]
			excluded := false
			for _, ex := range exclude {
				if candidate == ex {
					excluded = true
					break
				}
			}
			if !excluded {
				return candidate
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
		replica1 := shardReplicaIDs[0]
		replica2 := pickRandomReplicaID(replica1)

		replicaPubKeys, err := getReplicaPubKeys(replica1, replica2)
		if err != nil {
			return [2]uint8{}, nil, err
		}

		return [2]uint8{replica1, replica2}, replicaPubKeys, nil
	case numReplicas >= 4:
		// Select two random replicas that are not the replicas
		// in our shardReplicaIDs:
		replica1 := pickRandomReplicaID(shardReplicaIDs[0], shardReplicaIDs[1])
		replica2 := pickRandomReplicaID(replica1, shardReplicaIDs[0], shardReplicaIDs[1])

		replicaPubKeys, err := getReplicaPubKeys(replica1, replica2)
		if err != nil {
			return [2]uint8{}, nil, err
		}

		return [2]uint8{replica1, replica2}, replicaPubKeys, nil
	}

	// unreachable
	panic("unreachable code path")
}
