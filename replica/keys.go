// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/nike"
	nikepem "github.com/katzenpost/hpqc/nike/pem"

	"github.com/katzenpost/katzenpost/core/utils"
)

const (
	EpochsToKeyGeneration = 4320
)

type EnvelopeKey struct {
	PrivateKey nike.PrivateKey
	PublicKey  nike.PublicKey
}

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

	datadir string
	log     *logging.Logger
	keys    map[uint64]*EnvelopeKey
	scheme  nike.Scheme
}

func NewEnvelopeKeys(scheme nike.Scheme, log *logging.Logger, datadir string, epoch uint64) (*EnvelopeKeys, error) {
	e := &EnvelopeKeys{
		datadir: datadir,
		log:     log,
		keys:    make(map[uint64]*EnvelopeKey),
		scheme:  scheme,
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
	return e, nil
}

func (k *EnvelopeKeys) Generate(replicaEpoch uint64) error {
	k.Lock()
	defer k.Unlock()
	keypair := NewEnvelopeKey(k.scheme)
	err := keypair.WriteKeyFiles(k.datadir, k.scheme, replicaEpoch)
	if err != nil {
		return err
	}
	k.keys[replicaEpoch] = keypair
	return nil
}

func (k *EnvelopeKeys) Prune() bool {
	epoch, _, _ := ReplicaNow()
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

func (k *EnvelopeKeys) GetKeypair(replicaEpoch uint64) (*EnvelopeKey, error) {
	k.Lock()
	defer k.Unlock()
	keypair, ok := k.keys[replicaEpoch]
	if !ok {
		return nil, errors.New("key for given replica epoch doesn't exist")
	}
	return keypair, nil
}
