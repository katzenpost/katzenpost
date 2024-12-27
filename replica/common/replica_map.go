// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package common contains code that is useful to replicas and couriers.
package common

import (
	"sync"

	"github.com/katzenpost/katzenpost/core/pki"
)

type ReplicaMap struct {
	sync.RWMutex
	replicas map[[32]byte]*pki.ReplicaDescriptor
}

func NewReplicaMap() *ReplicaMap {
	return &ReplicaMap{
		replicas: make(map[[32]byte]*pki.ReplicaDescriptor),
	}
}

func (r *ReplicaMap) GetReplicaDescriptor(nodeID *[32]byte) (*pki.ReplicaDescriptor, bool) {
	r.RLock()
	ret, ok := r.replicas[*nodeID]
	r.RUnlock()
	// NOTE(david): make copy of pki.ReplicaDescriptor? it might be needed, later to avoid
	// data races if one threat mutates the descriptor.
	return ret, ok
}

func (r *ReplicaMap) Replace(newMap map[[32]byte]*pki.ReplicaDescriptor) {
	r.Lock()
	r.replicas = newMap
	r.Unlock()
}

func (r *ReplicaMap) Copy() map[[32]byte]*pki.ReplicaDescriptor {
	ret := make(map[[32]byte]*pki.ReplicaDescriptor)
	r.RLock()
	for k, v := range r.replicas {
		ret[k] = v
	}
	r.RUnlock()
	return ret
}
