// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !thinclient

package common

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/mrhybrid"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"

	"github.com/katzenpost/katzenpost/core/utils"
)

var KEMScheme kem.Scheme = kemschemes.ByName("mceliece348864-X25519")
var MRHybridScheme = mrhybrid.NewScheme(KEMScheme)

// EnvelopeKey encapsulates the public and private KEM keys.
type EnvelopeKey struct {
	PrivateKey kem.PrivateKey
	PublicKey  kem.PublicKey
}

// NewEnvelopeKey creates a new EnvelopeKey type.
func NewEnvelopeKey(scheme kem.Scheme) *EnvelopeKey {
	if scheme == nil {
		panic("replica KEM scheme is nil")
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

// EnvelopeKeyFromFiles loads the PEM key files from disk.
func EnvelopeKeyFromFiles(dataDir string, scheme kem.Scheme, epoch uint64) (*EnvelopeKey, error) {
	e := &EnvelopeKey{}
	privKeyFile, pubKeyFile := e.KeyFileNames(dataDir, scheme, epoch)

	if utils.BothExists(privKeyFile, pubKeyFile) {
		privateKey, err := kempem.FromPrivatePEMFile(privKeyFile, scheme)
		if err != nil {
			return nil, err
		}
		publicKey, err := kempem.FromPublicPEMFile(pubKeyFile, scheme)
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
	// not reached
}

func (e *EnvelopeKey) KeyFileNames(dataDir string, scheme kem.Scheme, epoch uint64) (string, string) {
	replicaPrivateKeyFile := filepath.Join(dataDir, fmt.Sprintf("replica.%d.private.pem", epoch))
	replicaPublicKeyFile := filepath.Join(dataDir, fmt.Sprintf("replica.%d.public.pem", epoch))
	return replicaPrivateKeyFile, replicaPublicKeyFile
}

func (e *EnvelopeKey) PurgeKeyFiles(dataDir string, scheme kem.Scheme, epoch uint64) {
	privKeyFile, pubKeyFile := e.KeyFileNames(dataDir, scheme, epoch)
	os.Remove(privKeyFile)
	os.Remove(pubKeyFile)
}

// WriteKeyFiles generates and writes new key files, or loads existing ones if
// they already exist. This ensures that a replica can safely restart or
// re-publish for the same epoch without errors.
func (e *EnvelopeKey) WriteKeyFiles(dataDir string, scheme kem.Scheme, epoch uint64) error {
	privKeyFile, pubKeyFile := e.KeyFileNames(dataDir, scheme, epoch)

	if utils.BothExists(privKeyFile, pubKeyFile) {
		privateKey, err := kempem.FromPrivatePEMFile(privKeyFile, scheme)
		if err != nil {
			return fmt.Errorf("failed to load existing private key: %w", err)
		}
		publicKey, err := kempem.FromPublicPEMFile(pubKeyFile, scheme)
		if err != nil {
			return fmt.Errorf("failed to load existing public key: %w", err)
		}
		e.PrivateKey = privateKey
		e.PublicKey = publicKey
		return nil
	} else if utils.BothNotExists(privKeyFile, pubKeyFile) {
		var err error
		e.PublicKey, e.PrivateKey, err = scheme.GenerateKeyPair()
		if err != nil {
			return err
		}
		err = kempem.PrivateKeyToFile(privKeyFile, e.PrivateKey)
		if err != nil {
			return err
		}
		err = kempem.PublicKeyToFile(pubKeyFile, e.PublicKey)
		if err != nil {
			return err
		}
	} else {
		return errors.New("found only one out of two key files for the keypair")
	}
	return nil
}
