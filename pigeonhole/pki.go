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

	shardIndexes := make([]uint8, 2)
	for i, shard := range shards {
		for j, replica := range doc.StorageReplicas {
			if hmac.Equal(shard.IdentityKey, replica.IdentityKey) {
				shardIndexes[i] = uint8(j)
				break
			}
		}
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

	switch {
	case numReplicas < 2:
		return [2]uint8{}, nil, errors.New("insufficient storage replicas: need at least 2 replicas")
	case numReplicas == 2:
		replicaPubKeys, err := getReplicaPubKeys(0, 1)
		if err != nil {
			return [2]uint8{}, nil, err
		}
		return [2]uint8{0, 1}, replicaPubKeys, nil
	case numReplicas == 3:
		// We cannot select two random replicas because we have only 3 replicas,
		// so only the second one is random.
		var replica2 uint8
		replica1 := shardIndexes[0]
		for {
			replica2 = uint8(secureRand.Intn(int(numReplicas)))
			if replica2 != replica1 {
				break
			}
		}

		replicaPubKeys, err := getReplicaPubKeys(replica1, replica2)
		if err != nil {
			return [2]uint8{}, nil, err
		}

		return [2]uint8{replica1, replica2}, replicaPubKeys, nil
	case numReplicas >= 4:
		// Select two random replicas that are not the replicas
		// in our shardIndexes:
		var replica1, replica2 uint8

		for {
			replica1 = uint8(secureRand.Intn(int(numReplicas)))
			if replica1 != shardIndexes[0] && replica1 != shardIndexes[1] {
				break
			}
		}

		for {
			replica2 = uint8(secureRand.Intn(int(numReplicas)))
			if replica2 != replica1 && replica2 != shardIndexes[0] && replica2 != shardIndexes[1] {
				break
			}
		}

		replicaPubKeys, err := getReplicaPubKeys(replica1, replica2)
		if err != nil {
			return [2]uint8{}, nil, err
		}

		return [2]uint8{replica1, replica2}, replicaPubKeys, nil
	}

	// unreacable
	panic("unreachable code path")
}
