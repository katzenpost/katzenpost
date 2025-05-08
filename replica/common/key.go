// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/katzenpost/hpqc/nike"
	nikepem "github.com/katzenpost/hpqc/nike/pem"
	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/utils"
)

var NikeScheme nike.Scheme = schemes.ByName("CTIDH1024-X25519")

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
