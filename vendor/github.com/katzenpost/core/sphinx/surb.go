// surb.go - Single Use Reply Blocks.
// Copyright (C) 2017  Yawning Angel.
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
	"errors"
	"io"

	"github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/sphinx/internal/crypto"
	"github.com/katzenpost/core/utils"
)

const (
	// SURBLength is the length of a Sphinx SURB in bytes.
	SURBLength = HeaderLength + constants.NodeIDLength + sprpKeyMaterialLength // 556 bytes.

	sprpKeyMaterialLength = crypto.SPRPKeyLength + crypto.SPRPIVLength
)

// NewSURB creates a new SURB with the provided path using the provided entropy
// source, and returns the SURB and decrypion keys.
func NewSURB(r io.Reader, path []*PathHop) ([]byte, []byte, error) {
	// Create a random SPRP key + iv for the recipient to use to encrypt
	// the payload when using the SURB.
	var keyPayload [sprpKeyMaterialLength]byte
	if _, err := io.ReadFull(r, keyPayload[:]); err != nil {
		return nil, nil, err
	}
	defer utils.ExplicitBzero(keyPayload[:])

	hdr, sprpKeys, err := createHeader(r, path)
	if err != nil {
		return nil, nil, err
	}

	// Serialize the SPRP keys into an opaque blob, in reverse order to ease
	// decryption.
	k := make([]byte, 0, sprpKeyMaterialLength*(len(path)+1))
	for i := len(path) - 1; i >= 0; i-- {
		k = append(k, sprpKeys[i].key[:]...)
		k = append(k, sprpKeys[i].iv[:]...)
		sprpKeys[i].Reset()
	}
	k = append(k, keyPayload[:]...)

	// Serialize the SURB into an opaque blob.
	surb := make([]byte, 0, SURBLength)
	surb = append(surb, hdr...)
	surb = append(surb, path[0].ID[:]...)
	surb = append(surb, keyPayload[:]...)

	return surb, k, nil
}

// NewPacketFromSURB creates a new reply Sphinx packet with the provided SURB
// and payload, and returns the packet and ID of the first hop.
func NewPacketFromSURB(surb, payload []byte) ([]byte, *[constants.NodeIDLength]byte, error) {
	const (
		idOff  = HeaderLength
		keyOff = idOff + constants.NodeIDLength
		ivOff  = keyOff + crypto.SPRPKeyLength
	)

	if len(surb) != SURBLength {
		return nil, nil, errors.New("sphinx: invalid packet, truncated SURB")
	}

	// Deserialize the SURB.
	hdr := surb[:HeaderLength]
	var nodeID [constants.NodeIDLength]byte
	var sprpKey [crypto.SPRPKeyLength]byte
	var sprpIV [crypto.SPRPIVLength]byte

	copy(nodeID[:], surb[idOff:keyOff])
	copy(sprpKey[:], surb[keyOff:ivOff])
	defer utils.ExplicitBzero(sprpKey[:])
	copy(sprpIV[:], surb[ivOff:])
	defer utils.ExplicitBzero(sprpIV[:])

	// Assemble the packet.
	pkt := make([]byte, 0, len(hdr)+PayloadTagLength+len(payload))
	pkt = append(pkt, hdr...)
	pkt = append(pkt, zeroBytes[:PayloadTagLength]...)
	pkt = append(pkt, payload...)

	// Encrypt the payload.
	b := crypto.SPRPEncrypt(&sprpKey, &sprpIV, pkt[len(hdr):])
	copy(pkt[len(hdr):], b)

	return pkt, &nodeID, nil
}

// DecryptSURBPayload decrypts the provided Sphinx payload generated via a SURB
// with the provided keys, and returns the plaintext.  The keys are obliterated
// at the end of this call.
func DecryptSURBPayload(payload, keys []byte) ([]byte, error) {
	defer utils.ExplicitBzero(keys)
	nrHops := len(keys) / sprpKeyMaterialLength
	if len(keys)%sprpKeyMaterialLength != 0 || nrHops < 1 {
		return nil, errors.New("sphinx: invalid SURB decryption keys")
	}
	if len(payload) < PayloadTagLength {
		return nil, errTruncatedPayload
	}

	k := keys[0:]
	var sprpKey [crypto.SPRPKeyLength]byte
	var sprpIV [crypto.SPRPIVLength]byte
	defer utils.ExplicitBzero(sprpKey[:])
	defer utils.ExplicitBzero(sprpIV[:])

	b := payload
	for i := 0; i < nrHops; i++ {
		copy(sprpKey[:], k[:crypto.SPRPKeyLength])
		copy(sprpIV[:], k[crypto.SPRPKeyLength:])
		k = k[sprpKeyMaterialLength:]
		if i == nrHops-1 {
			b = crypto.SPRPDecrypt(&sprpKey, &sprpIV, b)
		} else {
			// Undo one *decrypt* operation done by the Unwrap.
			b = crypto.SPRPEncrypt(&sprpKey, &sprpIV, b)
		}
	}

	// Authenticate the payload.
	if !utils.CtIsZero(b[:PayloadTagLength]) {
		return nil, errInvalidTag
	}

	return b[PayloadTagLength:], nil
}
