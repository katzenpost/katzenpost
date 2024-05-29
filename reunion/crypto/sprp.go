// sprp.go - SPRP wrapper.
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

package crypto

import (
	"gitlab.com/yawning/aez.git"
)

const (
	// SPRPMinimumBlockLength is the minimum block length of the SPRP.
	SPRPMinimumBlockLength = 32

	// SPRPKeyLength is the key size of the SPRP in bytes.
	SPRPKeyLength = 48

	// SPRPIVLength is the IV size of the SPRP in bytes.
	SPRPIVLength = 16
)

// SPRPEncrypt returns the ciphertext of the message msg, encrypted via the
// Sphinx SPRP with the provided key and IV.
func SPRPEncrypt(key *[SPRPKeyLength]byte, iv *[SPRPIVLength]byte, msg []byte) []byte {
	return aez.Encrypt(key[:], iv[:], nil, 0, msg, nil)
}

// SPRPDecrypt returns the plaintext of the message msg, decrypted via the
// Sphinx SPRP with the provided key and IV.
func SPRPDecrypt(key *[SPRPKeyLength]byte, iv *[SPRPIVLength]byte, msg []byte) []byte {
	dst, ok := aez.Decrypt(key[:], iv[:], nil, 0, msg, nil)
	if !ok {
		// Not covered by unit tests because this indicates a bug in the AEZ
		// implementation, that is hard to force.
		panic("crypto/SPRPDecrypt: BUG - aez.Decrypt failed with tau = 0")

	}
	return dst
}
