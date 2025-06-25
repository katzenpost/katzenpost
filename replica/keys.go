// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"errors"
	"sync"
	"time"

	replicaCommon "github.com/katzenpost/katzenpost/replica/common"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/nike"

	"github.com/katzenpost/katzenpost/core/worker"
)

const (
	// GracePeriod is the duration after key expirey that we keep the keys.
	GracePeriod = 3 * time.Hour
)

type EnvelopeKeys struct {
	worker.Worker

	log     *logging.Logger
	datadir string
	scheme  nike.Scheme

	keysLock *sync.RWMutex
	keys     map[uint64]*replicaCommon.EnvelopeKey
}

func NewEnvelopeKeys(scheme nike.Scheme, log *logging.Logger, datadir string, epoch uint64) (*EnvelopeKeys, error) {
	e := &EnvelopeKeys{
		datadir:  datadir,
		log:      log,
		keys:     make(map[uint64]*replicaCommon.EnvelopeKey),
		keysLock: new(sync.RWMutex),
		scheme:   scheme,
	}
	keypair, err := replicaCommon.EnvelopeKeyFromFiles(datadir, scheme, epoch)
	if err == nil {
		e.keys[epoch] = keypair
	} else {
		err = e.Generate(epoch)
		if err != nil {
			return nil, err
		}
	}
	e.Go(e.worker)
	return e, nil
}

// NOTE: this is where keys are destroyed.
// Key creation is triggered by the PKI worker
// which also uploads our replica descriptor
// to the dirauth nodes.
func (k *EnvelopeKeys) worker() {
	_, _, till := replicaCommon.ReplicaNow()
	gctimer := time.NewTimer(till + GracePeriod)
	defer func() {
		k.log.Debugf("Halting EnvelopeKeys worker.")
		gctimer.Stop()
	}()

	for {
		var gctimerFired bool

		select {
		case <-k.HaltCh():
			k.log.Debug("Terminating gracefully.")
			return
		case <-gctimer.C:
			gctimerFired = true
		}

		if !gctimerFired && !gctimer.Stop() {
			select {
			case <-k.HaltCh():
				k.log.Debug("Terminating gracefully.")
				return
			case <-gctimer.C:
			}
		}

		if gctimerFired {
			didPrune := k.Prune()
			if didPrune {
				k.log.Info("EnvelopeKeys GC worker pruned old keys")
			}
		}

		_, _, till := replicaCommon.ReplicaNow()
		gctimer.Reset(till + GracePeriod)
	}
}

func (k *EnvelopeKeys) Generate(replicaEpoch uint64) error {
	k.keysLock.Lock()
	defer k.keysLock.Unlock()
	keypair := replicaCommon.NewEnvelopeKey(k.scheme)
	err := keypair.WriteKeyFiles(k.datadir, k.scheme, replicaEpoch)
	if err != nil {
		return err
	}
	k.keys[replicaEpoch] = keypair
	return nil
}

func (k *EnvelopeKeys) Prune() bool {
	epoch, _, _ := replicaCommon.ReplicaNow()
	didPrune := false
	k.keysLock.Lock()
	defer k.keysLock.Unlock()
	for key, keypair := range k.keys {
		if key < epoch-1 {
			k.log.Debugf("Purging expired key for epoch: %v", key)
			// Remove key files from disk
			keypair.PurgeKeyFiles(k.datadir, k.scheme, key)
			delete(k.keys, key)
			didPrune = true
		}
	}
	return didPrune
}

func (k *EnvelopeKeys) GetKeypair(replicaEpoch uint64) (*replicaCommon.EnvelopeKey, error) {
	k.keysLock.RLock()
	defer k.keysLock.RUnlock()
	keypair, ok := k.keys[replicaEpoch]
	if !ok {
		return nil, errors.New("key for given replica epoch doesn't exist")
	}
	return keypair, nil
}

func (k *EnvelopeKeys) EnsureKey(replicaEpoch uint64) (*replicaCommon.EnvelopeKey, error) {
	// Check if the requested epoch is too old to generate a key for
	// Allow keys for a reasonable range of past epochs, but reject very old ones
	currentEpoch, _, _ := replicaCommon.ReplicaNow()
	if replicaEpoch < currentEpoch-15 {
		return nil, errors.New("cannot generate key for epoch that is too old")
	}

	keypair, err := k.GetKeypair(replicaEpoch)
	if err != nil {
		err = k.Generate(replicaEpoch)
		if err != nil {
			return nil, err
		}
		keypair, err = k.GetKeypair(replicaEpoch)
		if err != nil {
			return nil, err
		}
	}
	return keypair, nil
}
