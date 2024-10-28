// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"sync"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/nike"

	"github.com/katzenpost/katzenpost/core/epochtime"
)

const (
	EpochsToKeyGeneration = 4320
)

type EnvelopeKey struct {
	PrivateKey nike.PrivateKey
	PublicKey  nike.PublicKey
}

func NewEnvelopeKey(scheme nike.Scheme) *EnvelopeKey {
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	e := &EnvelopeKey{
		PrivateKey: sk,
		PublicKey:  pk,
	}
	return e
}

type EnvelopeKeys struct {
	sync.Mutex

	log    *logging.Logger
	keys   map[uint64]*EnvelopeKey
	scheme nike.Scheme
}

func (k *EnvelopeKeys) init() error {
	// Generate/load the initial set of keys.
	epoch, _, _ := epochtime.Now()
	k.Generate(epoch)
	return nil
}

func (k *EnvelopeKeys) Generate(baseEpoch uint64) {
	k.Lock()
	defer k.Unlock()
	for e := baseEpoch; e < baseEpoch+NumPKIDocsToFetch; e++ {
		// Skip keys that we already have.
		if _, ok := k.keys[e]; ok {
			continue
		}
		kk := NewEnvelopeKey(k.scheme)
		k.keys[e] = kk
	}
}

func (k *EnvelopeKeys) Prune() bool {
	epoch, _, _ := epochtime.Now()
	didPrune := false

	k.Lock()
	defer k.Unlock()

	for key, _ := range k.keys {
		if key < epoch-1 {
			k.log.Debugf("Purging expired key for epoch: %v", key)
			delete(k.keys, key)
			didPrune = true
		}
	}

	return didPrune
}
