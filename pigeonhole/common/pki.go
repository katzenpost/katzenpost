// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package common contains code that is useful to pigeonhole clients and Couriers.
package common

import (
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
	maxReplica := uint8(len(doc.StorageReplicas) - 1)
	replica1 := uint8(secureRand.Intn(int(maxReplica)))
	var replica2 uint8
	for replica2 == replica1 {
		replica2 = uint8(secureRand.Intn(int(maxReplica)))
	}

	replicaPubKeys := make([]nike.PublicKey, 2)
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	for i, replicaNum := range [2]uint8{replica1, replica2} {
		desc, err := replicaCommon.ReplicaNum(replicaNum, doc)
		if err != nil {
			return [2]uint8{}, nil, err
		}
		replicaPubKeys[i], err = replicaCommon.NikeScheme.UnmarshalBinaryPublicKey(desc.EnvelopeKeys[replicaEpoch])
		if err != nil {
			return [2]uint8{}, nil, err
		}
	}
	return [2]uint8{replica1, replica2}, replicaPubKeys, nil
}
