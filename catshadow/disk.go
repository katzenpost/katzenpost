// SPDX-FileCopyrightText: 2019, David Stainton <dawuud@riseup.net>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// disk.go - statefile worker, serialization and encryption
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package catshadow

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/secretbox"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign/ed25519"

	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/memspool/client"
)

const (
	keySize   = 32
	nonceSize = 24
)

var (
	DecryptStateFailed = errors.New("failed to decrypted statefile")
)

// State is the struct type representing the Client's state
// which is encrypted and persisted to disk.
type State struct {
	SpoolReadDescriptor *client.SpoolReadDescriptor
	Contacts            []*Contact
	Providers           []*pki.MixDescriptor
	Conversations       map[string]map[MessageID]*Message
	Blob                map[string][]byte
}

type CBORState struct {
	SpoolReadDescriptor *client.CBORSpoolReadDescriptor
	Contacts            []*Contact
	Providers           []*pki.MixDescriptor
	Conversations       map[string]map[MessageID]*Message
	Blob                map[string][]byte
}

// StateWriter takes ownership of the Client's encrypted statefile
// and has a worker goroutine which writes updates to disk.
type StateWriter struct {
	worker.Worker

	log *logging.Logger

	stateCh   chan []byte
	stateFile string

	key *[32]byte
}

func encryptState(state []byte, key *[32]byte) ([]byte, error) {
	nonce := [nonceSize]byte{}
	_, err := rand.Reader.Read(nonce[:])
	if err != nil {
		return nil, err
	}
	ciphertext := secretbox.Seal(nil, state, &nonce, key)
	ciphertext = append(nonce[:], ciphertext...)
	return ciphertext, nil
}

func decryptState(ciphertext []byte, key *[32]byte) ([]byte, error) {
	nonce := [nonceSize]byte{}
	copy(nonce[:], ciphertext[:nonceSize])
	ciphertext = ciphertext[nonceSize:]
	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, key)
	if !ok {
		return nil, DecryptStateFailed
	}
	return plaintext, nil
}

func stretchKey(passphrase []byte) *[32]byte {
	secret := argon2.Key(passphrase, nil, 3, 32*1024, 4, keySize)
	key := [keySize]byte{}
	copy(key[:], secret)
	return &key
}

func decryptStateFile(stateFile string, key *[32]byte) (*State, error) {
	rawFile, err := os.ReadFile(stateFile)
	if err != nil {
		return nil, err
	}
	plaintext, err := decryptState(rawFile, key)
	if err != nil {
		return nil, err
	}
	state := new(State)
	state.SpoolReadDescriptor = new(client.SpoolReadDescriptor)
	_, state.SpoolReadDescriptor.PrivateKey, err = ed25519.Scheme().GenerateKey()
	if err != nil {
		return nil, err
	}
	if _, err = cbor.UnmarshalFirst(plaintext, &state); err != nil {
		return nil, err
	}
	return state, nil
}

func encryptStateFile(stateFile string, state []byte, key *[32]byte) error {
	outFn := stateFile
	tmpFn := fmt.Sprintf("%s.tmp", stateFile)
	backupFn := fmt.Sprintf("%s~", stateFile)
	ciphertext, err := encryptState(state, key)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(tmpFn, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = out.Write(ciphertext)
	if err != nil {
		return err
	}
	err = out.Sync()
	if err != nil {
		return err
	}
	if err := os.Rename(outFn, backupFn); err != nil && !os.IsNotExist(err) {
		return err
	}
	dirFn := filepath.Dir(stateFile)
	dir, err := os.Open(dirFn)
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		return err
	}
	if err := os.Rename(tmpFn, outFn); err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		return err
	}
	return dir.Close()
}

// LoadStateWriter decrypts the given stateFile and returns the State
// as well as a new StateWriter.
func LoadStateWriter(log *logging.Logger, stateFile string, passphrase []byte) (*StateWriter, *State, error) {
	worker := &StateWriter{
		log:       log,
		stateCh:   make(chan []byte),
		stateFile: stateFile,
	}
	key := stretchKey(passphrase)
	state, err := decryptStateFile(stateFile, key)
	if err != nil {
		return nil, nil, err
	}
	worker.key = key
	return worker, state, nil
}

// NewStateWriter is a constructor for StateWriter which is to be used when creating
// the statefile for the first time.
func NewStateWriter(log *logging.Logger, stateFile string, passphrase []byte) (*StateWriter, error) {
	key := stretchKey(passphrase)
	worker := &StateWriter{
		log:       log,
		stateCh:   make(chan []byte),
		stateFile: stateFile,
		key:       key,
	}
	return worker, nil
}

// Start starts the StateWriter's worker goroutine.
func (w *StateWriter) Start() {
	w.log.Debug("StateWriter starting worker")
	w.Go(w.worker)
}

func (w *StateWriter) writeState(payload []byte) error {
	return encryptStateFile(w.stateFile, payload, w.key)
}

func (w *StateWriter) worker() {
	for {
		select {
		case <-w.HaltCh():
			w.log.Debugf("Terminating gracefully.")
			return
		case newState := <-w.stateCh:
			err := w.writeState(newState)
			if err != nil {
				w.log.Errorf("Failure to write state to disk: %s", err)
				panic(err)
			}
		}
	}
}
