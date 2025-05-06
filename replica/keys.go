// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/nike"
	nikepem "github.com/katzenpost/hpqc/nike/pem"

	"github.com/katzenpost/katzenpost/core/utils"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/courier/common"
)

const (
	// GracePeriod is the duration after key expirey that we keep the keys.
	GracePeriod = 3 * time.Hour
)

// EnvelopeKey encapsulates the public and private NIKE keys.
type EnvelopeKey struct {
	PrivateKey nike.PrivateKey
	PublicKey  nike.PublicKey
}

// NewEnvelopeKey creates a new EnvelopeKey type.
func NewEnvelopeKey(scheme nike.Scheme) *EnvelopeKey {
	if scheme == nil {
		panic("replica NIKE scheme is nil")
	}
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

// NewEnvelopeKeyFromFiles loads the PEM key files from disk.
func NewEnvelopeKeyFromFiles(dataDir string, scheme nike.Scheme, epoch uint64) (*EnvelopeKey, error) {
	e := &EnvelopeKey{}
	privKeyFile, pubKeyFile := e.KeyFileNames(dataDir, scheme, epoch)
	if utils.BothExists(privKeyFile, pubKeyFile) {
		privateKey, err := nikepem.FromPrivatePEMFile(privKeyFile, scheme)
		if err != nil {
			return nil, err
		}
		publicKey, err := nikepem.FromPublicPEMFile(pubKeyFile, scheme)
		if err != nil {
			return nil, err
		}
		e.PrivateKey = privateKey
		e.PublicKey = publicKey
		return e, nil
	} else if utils.BothNotExists(privKeyFile, pubKeyFile) {
		return nil, errors.New("key files do not exist")
	} else {
		return nil, errors.New("only one key file exists")
	}
	// no reached
}

func (e *EnvelopeKey) KeyFileNames(dataDir string, scheme nike.Scheme, epoch uint64) (string, string) {
	replicaPrivateKeyFile := filepath.Join(dataDir, fmt.Sprintf("replica.%d.private.pem", epoch))
	replicaPublicKeyFile := filepath.Join(dataDir, fmt.Sprintf("replica.%d.public.pem", epoch))
	return replicaPrivateKeyFile, replicaPublicKeyFile
}

func (e *EnvelopeKey) PurgeKeyFiles(dataDir string, scheme nike.Scheme, epoch uint64) {
	privKeyFile, pubKeyFile := e.KeyFileNames(dataDir, scheme, epoch)
	os.Remove(privKeyFile)
	os.Remove(pubKeyFile)
}

func (e *EnvelopeKey) WriteKeyFiles(dataDir string, scheme nike.Scheme, epoch uint64) error {
	privKeyFile, pubKeyFile := e.KeyFileNames(dataDir, scheme, epoch)
	if utils.BothExists(privKeyFile, pubKeyFile) {
		return errors.New("key files already exist")
	} else if utils.BothNotExists(privKeyFile, pubKeyFile) {
		var err error
		e.PublicKey, e.PrivateKey, err = scheme.GenerateKeyPair()
		if err != nil {
			return err
		}
		err = nikepem.PrivateKeyToFile(privKeyFile, e.PrivateKey, scheme)
		if err != nil {
			return err
		}
		err = nikepem.PublicKeyToFile(pubKeyFile, e.PublicKey, scheme)
		if err != nil {
			return err
		}
	} else {
		return errors.New("found only one out of two key files for the keypair")
	}
	return nil
}

type EnvelopeKeys struct {
	worker.Worker

	log     *logging.Logger
	datadir string
	scheme  nike.Scheme

	keysLock *sync.RWMutex
	keys     map[uint64]*EnvelopeKey
}

func NewEnvelopeKeys(scheme nike.Scheme, log *logging.Logger, datadir string, epoch uint64) (*EnvelopeKeys, error) {
	e := &EnvelopeKeys{
		datadir:  datadir,
		log:      log,
		keys:     make(map[uint64]*EnvelopeKey),
		keysLock: new(sync.RWMutex),
		scheme:   scheme,
	}
	keypair, err := NewEnvelopeKeyFromFiles(datadir, scheme, epoch)
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
	_, _, till := common.ReplicaNow()
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

		_, _, till := common.ReplicaNow()
		gctimer.Reset(till + GracePeriod)
	}
}

func (k *EnvelopeKeys) Generate(replicaEpoch uint64) error {
	k.keysLock.Lock()
	defer k.keysLock.Unlock()
	keypair := NewEnvelopeKey(k.scheme)
	err := keypair.WriteKeyFiles(k.datadir, k.scheme, replicaEpoch)
	if err != nil {
		return err
	}
	k.keys[replicaEpoch] = keypair
	return nil
}

func (k *EnvelopeKeys) Prune() bool {
	epoch, _, _ := common.ReplicaNow()
	didPrune := false
	k.keysLock.Lock()
	defer k.keysLock.Unlock()
	for key, _ := range k.keys {
		if key < epoch-1 {
			k.log.Debugf("Purging expired key for epoch: %v", key)
			delete(k.keys, key)
			didPrune = true
		}
	}
	return didPrune
}

func (k *EnvelopeKeys) GetKeypair(replicaEpoch uint64) (*EnvelopeKey, error) {
	k.keysLock.RLock()
	defer k.keysLock.RUnlock()
	keypair, ok := k.keys[replicaEpoch]
	if !ok {
		return nil, errors.New("key for given replica epoch doesn't exist")
	}
	return keypair, nil
}

func (k *EnvelopeKeys) EnsureKey(replicaEpoch uint64) (*EnvelopeKey, error) {
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
