// pem.go - PEM file write barrier.
//
// Copyright (C) 2022  David Stainton.
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

package pem

import (
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/katzenpost/katzenpost/core/utils"
)

// KeyMaterial
type KeyMaterial interface {
	FromBytes([]byte) error

	Bytes() []byte

	KeyType() string
}

func BothExists(a, b string) bool {
	if Exists(a) && Exists(b) {
		return true
	}
	return false
}

func BothNotExists(a, b string) bool {
	if !Exists(a) && !Exists(b) {
		return true
	}
	return false
}

func Exists(f string) bool {
	if _, err := os.Stat(f); err == nil {
		return true
	} else if errors.Is(err, os.ErrNotExist) {
		return false
	} else {
		panic(err)
	}
}

func ToFile(f string, key KeyMaterial) error {
	keyType := strings.ToUpper(key.KeyType())

	if utils.CtIsZero(key.Bytes()) {
		return fmt.Errorf("WriteToPEMFile/%s: attempted to serialize scrubbed key", keyType)
	}
	blk := &pem.Block{
		Type:  keyType,
		Bytes: key.Bytes(),
	}
	out, err := os.OpenFile(f, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	outBuf := pem.EncodeToMemory(blk)
	writeCount, err := out.Write(outBuf)
	if err != nil {
		return err
	}
	if writeCount != len(outBuf) {
		return errors.New("partial write failure")
	}
	err = out.Sync()
	if err != nil {
		return err
	}
	return out.Close()
}

func FromFile(f string, key KeyMaterial) error {
	keyType := strings.ToUpper(key.KeyType())

	buf, err := os.ReadFile(f)
	if err != nil {
		return fmt.Errorf("pem.FromFile error: %s", err)
	}
	blk, _ := pem.Decode(buf)
	if blk == nil {
		return fmt.Errorf("failed to decode PEM file %v", f)
	}
	if blk.Type != keyType {
		return fmt.Errorf("attempted to decode PEM file with wrong key type %v != %v", blk.Type, keyType)
	}
	return key.FromBytes(blk.Bytes)
}
