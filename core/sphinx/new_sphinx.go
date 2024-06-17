// new_sphinx.go - New Sphinx API
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

package sphinx

import (
	"io"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
)

// NewPacket creates a forward Sphinx packet with the provided path and
// payload, using the provided entropy source.
func (s *Sphinx) NewPacket(r io.Reader, path []*PathHop, payload []byte) ([]byte, error) {
	if s.nike == nil {
		return s.newKEMPacket(r, path, payload)
	}

	if s.kem == nil {
		return s.newNikePacket(r, path, payload)
	}

	panic("NewPacket error, KEM and NIKE, one must be set and the other must be nil")
}

// Unwrap unwraps the provided Sphinx packet pkt in-place, using the provided
// NIKE or KEM private key, and returns the payload (if applicable), replay tag, and
// routing info command vector.
func (s *Sphinx) Unwrap(privKey interface{}, pkt []byte) ([]byte, []byte, []commands.RoutingCommand, error) {
	if s.nike == nil {
		return s.unwrapKem(privKey.(kem.PrivateKey), pkt)
	}

	if s.kem == nil {
		return s.unwrapNike(privKey.(nike.PrivateKey), pkt)
	}

	panic("Unwrap error, KEM and NIKE both cannot be onil")
}

// NewSURB creates a new SURB with the provided path using the provided entropy
// source, and returns the SURB and decrypion keys.
func (s *Sphinx) NewSURB(r io.Reader, path []*PathHop) ([]byte, []byte, error) {
	if s.nike == nil {
		return s.newKemSURB(r, path)
	}

	if s.kem == nil {
		return s.newNikeSURB(r, path)
	}

	panic("NewSURB error, KEM and NIKE both cannot be onil")
}
