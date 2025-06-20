// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package common contains code that is useful to replicas and couriers.
package common

import (
	"errors"

	"github.com/katzenpost/katzenpost/core/pki"
)

func ReplicaNum(n uint8, doc *pki.Document) (*pki.ReplicaDescriptor, error) {
	if n < uint8(len(doc.StorageReplicas)) {
		return doc.StorageReplicas[n], nil
	} else {
		return nil, errors.New("ReplicaNum: n is out of bounds of doc.StorageReplicas")
	}
}
