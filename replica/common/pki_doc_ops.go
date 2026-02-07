// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package common contains code that is useful to replicas and couriers.
package common

import (
	"github.com/katzenpost/katzenpost/core/pki"
)

// ReplicaNum looks up a replica by its static ReplicaID.
// The replicaID parameter is the static uint8 identifier assigned to a replica,
// not an array index into StorageReplicas.
func ReplicaNum(replicaID uint8, doc *pki.Document) (*pki.ReplicaDescriptor, error) {
	return doc.GetReplicaNodeByReplicaID(replicaID)
}
