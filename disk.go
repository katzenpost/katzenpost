// disk.go - statefile worker, serialization and encryption
// Copyright (C) 2019  David Stainton.
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
	"io/ioutil"
	"os"

	"github.com/katzenpost/channels"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/worker"
	"github.com/ugorji/go/codec"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/secretbox"
	"gopkg.in/op/go-logging.v1"
)

const (
	StateFileName = "catshadow_statefile"
	keySize       = 32
	nonceSize     = 24
)

type State struct {
	SpoolReaderChan *channels.UnreliableSpoolReaderChannel
	Contacts        []*Contact
	LinkKey         *ecdh.PrivateKey
}

type StateWriter struct {
	worker.Worker

	log *logging.Logger

	stateCh   chan []byte
	stateFile string

	key   [32]byte
	nonce [24]byte
}

func LoadStateWriter(log *logging.Logger, stateFile string, passphrase []byte) (*StateWriter, *State, error) {
	secret := argon2.Key(passphrase, nil, 3, 32*1024, 4, keySize+nonceSize)
	worker := &StateWriter{
		log:       log,
		stateCh:   make(chan []byte),
		stateFile: stateFile,
	}
	copy(worker.key[:], secret[0:32])
	copy(worker.nonce[:], secret[32:])

	ciphertext, err := ioutil.ReadFile(stateFile)
	if err != nil {
		return nil, nil, err
	}
	plaintext, ok := secretbox.Open(nil, ciphertext, &worker.nonce, &worker.key)
	if !ok {
		return nil, nil, errors.New("failed to decrypted statefile")
	}
	state := new(State)
	err = codec.NewDecoderBytes(plaintext, cborHandle).Decode(state)
	if err != nil {
		return nil, nil, err
	}
	return worker, state, nil
}

func NewStateWriter(log *logging.Logger, stateFile string, passphrase []byte) (*StateWriter, error) {
	secret := argon2.Key(passphrase, nil, 3, 32*1024, 4, keySize+nonceSize)
	worker := &StateWriter{
		log:       log,
		stateCh:   make(chan []byte),
		stateFile: stateFile,
	}
	copy(worker.key[:], secret[0:32])
	copy(worker.nonce[:], secret[32:])
	return worker, nil
}

func (w *StateWriter) Start() {
	w.log.Debug("StateWriter starting worker")
	w.Go(w.worker)
}

func (w *StateWriter) GetState() (*State, error) {
	ciphertext, err := ioutil.ReadFile(w.stateFile)
	if err != nil {
		return nil, err
	}
	plaintext, ok := secretbox.Open(nil, ciphertext, &w.nonce, &w.key)
	if !ok {
		return nil, errors.New("failed to decrypted statefile")
	}
	state := new(State)
	err = codec.NewDecoderBytes(plaintext, cborHandle).Decode(&state)
	if err != nil {
		return nil, err
	}
	return state, nil
}

func (w *StateWriter) writeState(payload []byte) error {
	ciphertext := secretbox.Seal(nil, payload, &w.nonce, &w.key)
	out, err := os.OpenFile(w.stateFile+".tmp", os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = out.Write(ciphertext)
	if err != nil {
		return err
	}
	if err := os.Remove(w.stateFile + "~"); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(w.stateFile, w.stateFile+"~"); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(w.stateFile+".tmp", w.stateFile); err != nil {
		return err
	}
	if err := os.Remove(w.stateFile + "~"); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
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
