// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	nikepem "github.com/katzenpost/hpqc/nike/pem"
	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/utils"
)

var NikeScheme nike.Scheme = schemes.ByName("CTIDH1024-X25519")
var MKEMNikeScheme = mkem.NewScheme(NikeScheme)

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

// EnvelopeKeyFromFiles loads the PEM key files from disk.
func EnvelopeKeyFromFiles(dataDir string, scheme nike.Scheme, epoch uint64) (*EnvelopeKey, error) {
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
	// not reached
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

// WriteKeyFiles generates and writes new key files, or loads existing ones if they already exist.
// This ensures that a replica can safely restart or re-publish for the same epoch without errors.
func (e *EnvelopeKey) WriteKeyFiles(dataDir string, scheme nike.Scheme, epoch uint64) error {
	privKeyFile, pubKeyFile := e.KeyFileNames(dataDir, scheme, epoch)

	if utils.BothExists(privKeyFile, pubKeyFile) {
		// Keys already exist for this epoch - load them instead of erroring.
		// This is a normal case when the replica restarts or re-publishes.
		privateKey, err := nikepem.FromPrivatePEMFile(privKeyFile, scheme)
		if err != nil {
			return fmt.Errorf("failed to load existing private key: %w", err)
		}
		publicKey, err := nikepem.FromPublicPEMFile(pubKeyFile, scheme)
		if err != nil {
			return fmt.Errorf("failed to load existing public key: %w", err)
		}
		e.PrivateKey = privateKey
		e.PublicKey = publicKey
		return nil
	} else if utils.BothNotExists(privKeyFile, pubKeyFile) {
		// Generate new keys
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
