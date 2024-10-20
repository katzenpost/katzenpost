// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package common contains code that is useful to replicas and couriers.
package common

import (
	"errors"
	"slices"

	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/katzenpost/core/pki"
)

func ReplicaSort(doc *pki.Document) ([]*pki.ReplicaDescriptor, error) {
	if doc.StorageReplicas == nil {
		return nil, errors.New("ReplicaEnumeration: doc.StorageReplicas is nil")
	}
	if len(doc.StorageReplicas) == 0 {
		return nil, errors.New("ReplicaEnumeration: doc.StorageReplicas is empty")
	}
	replicas := make([]*pki.ReplicaDescriptor, 0, len(doc.StorageReplicas))
	for _, replica := range doc.StorageReplicas {
		replicas = append(replicas, replica)
	}
	slices.SortFunc(replicas, func(a, b *pki.ReplicaDescriptor) int {
		ha := blake2b.Sum256(a.IdentityKey)
		hb := blake2b.Sum256(b.IdentityKey)
		return slices.Compare(ha[:], hb[:])
	})
	return replicas, nil
}
