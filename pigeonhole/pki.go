// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package common contains code that is useful to pigeonhole clients and Couriers.
package pigeonhole

import (
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
func GetRandomIntermediateReplicas(doc *cpki.Document) ([2]uint8, []nike.PublicKey, error) {
	// Validate PKI document
	if doc == nil {
		return [2]uint8{}, nil, errors.New("PKI document is nil")
	}
	if doc.StorageReplicas == nil {
		return [2]uint8{}, nil, errors.New("PKI document has nil StorageReplicas")
	}

	numReplicas := uint8(len(doc.StorageReplicas))
	if numReplicas < 2 {
		return [2]uint8{}, nil, errors.New("insufficient storage replicas: need at least 2")
	}

	replica1 := uint8(secureRand.Intn(int(numReplicas)))
	replica2 := uint8(secureRand.Intn(int(numReplicas)))
	for replica2 == replica1 {
		replica2 = uint8(secureRand.Intn(int(numReplicas)))
	}

	replicaPubKeys := make([]nike.PublicKey, 2)
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	for i, replicaNum := range [2]uint8{replica1, replica2} {
		desc, err := replicaCommon.ReplicaNum(replicaNum, doc)
		if err != nil {
			return [2]uint8{}, nil, err
		}
		keyBytes, exists := desc.EnvelopeKeys[replicaEpoch]
		if !exists {
			return [2]uint8{}, nil, fmt.Errorf("no envelope key found for replica %d at epoch %d", replicaNum, replicaEpoch)
		}
		if len(keyBytes) == 0 {
			return [2]uint8{}, nil, fmt.Errorf("empty envelope key for replica %d at epoch %d", replicaNum, replicaEpoch)
		}
		replicaPubKeys[i], err = replicaCommon.NikeScheme.UnmarshalBinaryPublicKey(keyBytes)
		if err != nil {
			return [2]uint8{}, nil, fmt.Errorf("failed to unmarshal key for replica %d (keySize=%d): %w", replicaNum, len(keyBytes), err)
		}
	}
	return [2]uint8{replica1, replica2}, replicaPubKeys, nil
}
