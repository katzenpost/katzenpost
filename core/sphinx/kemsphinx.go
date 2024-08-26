// kemsphinx.go - KEM Sphinx Packet Format.
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
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"github.com/katzenpost/hpqc/kem"

	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/sphinx/internal/crypto"
	"github.com/katzenpost/katzenpost/core/utils"
)

// NewKEMSphinx creates a new instance of KEMSphinx, the Sphinx
// nested cryptographic packet format that uses a KEM instead of a NIKE.
// This implies lots of packet over, one KEM encapsulation per hop actually.
// But since we no longer use 2400 maude modems let's rock out with
// our Hybrid Classical + PQ KEM Sphinx.
func NewKEMSphinx(k kem.Scheme, geometry *geo.Geometry) *Sphinx {
	if k == nil {
		panic("KEM Scheme is nil")
	}
	s := &Sphinx{
		kem:      k,
		geometry: geometry,
	}
	return s
}

func (s *Sphinx) newKemSURB(r io.Reader, path []*PathHop) ([]byte, []byte, error) {
	// Create a random SPRP key + iv for the recipient to use to encrypt
	// the payload when using the SURB.
	var keyPayload [sprpKeyMaterialLength]byte
	if _, err := io.ReadFull(r, keyPayload[:]); err != nil {
		return nil, nil, err
	}
	defer utils.ExplicitBzero(keyPayload[:])

	hdr, sprpKeys, err := s.createKEMHeader(r, path)
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
	surb := make([]byte, 0, s.geometry.SURBLength)
	surb = append(surb, hdr...)
	surb = append(surb, path[0].ID[:]...)
	surb = append(surb, keyPayload[:]...)

	return surb, k, nil
}

func (s *Sphinx) newKEMPacket(r io.Reader, path []*PathHop, payload []byte) ([]byte, error) {
	if len(payload) != s.geometry.ForwardPayloadLength {
		return nil, fmt.Errorf("invalid payload length: %d, expected %d", len(payload), s.geometry.ForwardPayloadLength)
	}

	hdr, sprpKeys, err := s.createKEMHeader(r, path)
	if err != nil {
		return nil, err
	}
	for _, v := range sprpKeys {
		defer v.Reset()
	}

	zeroBytes := make([]byte, s.geometry.PerHopRoutingInfoLength)

	// Assemble the packet.
	pkt := make([]byte, 0, len(hdr)+s.geometry.PayloadTagLength+len(payload))
	pkt = append(pkt, hdr...)
	pkt = append(pkt, zeroBytes[:s.geometry.PayloadTagLength]...)
	pkt = append(pkt, payload...)

	// Encrypt the payload.
	b := pkt[len(hdr):]
	for i := len(path) - 1; i >= 0; i-- {
		k := sprpKeys[i]
		b = crypto.SPRPEncrypt(&k.key, &k.iv, b)
	}
	copy(pkt[len(hdr):], b)

	return pkt, nil
}

/*
KEM Sphinx header elements:

1. version number (MACed but not encrypted)
2. one KEM ciphertext for use with the next hop
3. encrypted per routing commands (containing KEM ciphertexts for each next hop)
4. MAC for this hop (authenticates header fields 1-4)
*/
func (s *Sphinx) createKEMHeader(r io.Reader, path []*PathHop) ([]byte, []*sprpKey, error) {
	nrHops := len(path)
	if nrHops > s.geometry.NrHops {
		return nil, nil, errors.New("sphinx: invalid path")
	}

	// Derive the key material for each hop.
	var err error
	var sharedSecret []byte
	kemElements := make([][]byte, nrHops)
	keys := make([]*crypto.PacketKeys, nrHops)

	if s.kem == nil {
		panic("sphinx: KEM object is nil")
	}

	for i := 0; i < nrHops; i++ {
		kemElements[i], sharedSecret, err = s.kem.Encapsulate(path[i].KEMPublicKey)
		if err != nil {
			panic(err)
		}
		defer utils.ExplicitBzero(sharedSecret)

		// set the second arg (NIKE interface object) to nil
		// so we don't need to generate blinding factors
		// for KEMSphinx.
		keys[i] = crypto.KDF(sharedSecret, nil)
		defer keys[i].Reset()
	}

	// Derive the routing_information keystream and encrypted padding for each
	// hop.
	riKeyStream := make([][]byte, nrHops)
	riPadding := make([][]byte, nrHops)

	for i := 0; i < nrHops; i++ {
		keyStream := make([]byte, s.geometry.RoutingInfoLength+s.geometry.PerHopRoutingInfoLength)
		defer utils.ExplicitBzero(keyStream)

		streamCipher := crypto.NewStream(&keys[i].HeaderEncryption, &keys[i].HeaderEncryptionIV)
		streamCipher.KeyStream(keyStream)
		streamCipher.Reset()

		ksLen := len(keyStream) - (i+1)*s.geometry.PerHopRoutingInfoLength
		riKeyStream[i] = keyStream[:ksLen]
		riPadding[i] = keyStream[ksLen:]
		if i > 0 {
			prevPadLen := len(riPadding[i-1])
			xorBytes(riPadding[i][:prevPadLen], riPadding[i][:prevPadLen], riPadding[i-1])
		}
	}

	// Create the routing_information block.
	var mac []byte
	var routingInfo []byte
	if skippedHops := s.geometry.NrHops - nrHops; skippedHops > 0 {
		routingInfo = make([]byte, skippedHops*s.geometry.PerHopRoutingInfoLength)
		_, err := io.ReadFull(rand.Reader, routingInfo)
		if err != nil {
			panic(err)
		}
	}
	zeroBytes := make([]byte, s.geometry.PerHopRoutingInfoLength)
	for i := nrHops - 1; i >= 0; i-- {
		isTerminal := i == nrHops-1

		riFragment, err := s.commandsToBytes(path[i].Commands, isTerminal)
		if err != nil {
			return nil, nil, err
		}
		if !isTerminal {
			nextCmd := &commands.NextNodeHop{}
			copy(nextCmd.ID[:], path[i+1].ID[:])
			copy(nextCmd.MAC[:], mac)
			riFragment = nextCmd.ToBytes(riFragment)
		}
		if padLen := s.geometry.PerHopRoutingInfoLength - len(riFragment); padLen > 0 {
			riFragment = append(riFragment, zeroBytes[:padLen]...)
		}
		if !isTerminal {
			copy(riFragment[s.geometry.PerHopRoutingInfoLength-s.kem.CiphertextSize():], kemElements[i+1])
		}

		routingInfo = append(riFragment, routingInfo...) // Prepend
		xorBytes(routingInfo, routingInfo, riKeyStream[i])

		m := crypto.NewMAC(&keys[i].HeaderMAC)
		defer m.Reset()
		m.Write(v0AD[:])
		m.Write(kemElements[i])
		m.Write(routingInfo)
		if i > 0 {
			m.Write(riPadding[i-1])
		}
		mac = m.Sum(nil)
	}

	// Assemble the completed Sphinx Packet Header and Sphinx Packet Payload
	// SPRP key vector.
	hdr := make([]byte, 0, s.geometry.HeaderLength)
	hdr = append(hdr, v0AD[:]...)
	hdr = append(hdr, kemElements[0]...)
	hdr = append(hdr, routingInfo...)
	hdr = append(hdr, mac...)

	sprpKeys := make([]*sprpKey, 0, nrHops)
	for i := 0; i < nrHops; i++ {
		v := keys[i]

		// The header encryption IV is reused for the SPRP because the keys
		// *and* more importantly the primitives are different.
		k := new(sprpKey)
		copy(k.key[:], v.PayloadEncryption[:])
		copy(k.iv[:], v.HeaderEncryptionIV[:])
		sprpKeys = append(sprpKeys, k)
	}

	return hdr, sprpKeys, nil
}

func (s *Sphinx) unwrapKem(privKey kem.PrivateKey, pkt []byte) ([]byte, []byte, []commands.RoutingCommand, error) {
	var (
		geOff      = 2
		riOff      = geOff + s.kem.CiphertextSize()
		macOff     = riOff + s.geometry.RoutingInfoLength
		payloadOff = macOff + crypto.MACLength
	)

	// Do some basic sanity checking, and validate the AD.
	if len(pkt) < s.geometry.HeaderLength {
		return nil, nil, nil, errors.New("KEMSphinx: invalid packet, truncated")
	}
	if subtle.ConstantTimeCompare(v0AD[:], pkt[:2]) != 1 {
		return nil, nil, nil, errors.New("KEMSphinx: invalid packet, unknown version")
	}

	var sharedSecret []byte
	defer utils.ExplicitBzero(sharedSecret)

	// Calculate the hop's shared secret, and replay_tag.
	kemCiphertext := pkt[geOff:riOff]
	sharedSecret, err := privKey.Scheme().Decapsulate(privKey, kemCiphertext)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("KEMSphinx: failed to decrypt KEM: %s", err)
	}

	replayTag := crypto.Hash(kemCiphertext)

	// Derive the various keys required for packet processing.
	// note we set the second arg (NIKE interface object) to nil
	// because we do not derive blinding factors for KEMSphinx!
	keys := crypto.KDF(sharedSecret, nil)
	defer keys.Reset()

	// Validate the Sphinx Packet Header.
	m := crypto.NewMAC(&keys.HeaderMAC)
	defer m.Reset()
	m.Write(pkt[0:macOff])
	mac := m.Sum(nil)

	if subtle.ConstantTimeCompare(pkt[macOff:macOff+crypto.MACLength], mac) != 1 {
		return nil, replayTag[:], nil, errors.New("KEMSphinx: invalid packet, MAC mismatch")
	}

	// Append padding to preserve length invariance, decrypt the (padded)
	// routing_info block, and extract the section for the current hop.
	b := make([]byte, s.geometry.RoutingInfoLength+s.geometry.PerHopRoutingInfoLength)
	copy(b[:s.geometry.RoutingInfoLength], pkt[riOff:riOff+s.geometry.RoutingInfoLength])
	stream := crypto.NewStream(&keys.HeaderEncryption, &keys.HeaderEncryptionIV)
	defer stream.Reset()
	stream.XORKeyStream(b[:], b[:])

	cmdBuf := b[:s.geometry.PerHopRoutingInfoLength-s.kem.CiphertextSize()]
	kemCiphertext = b[s.geometry.PerHopRoutingInfoLength-s.kem.CiphertextSize() : s.geometry.PerHopRoutingInfoLength]
	newRoutingInfo := b[s.geometry.PerHopRoutingInfoLength:]

	// Parse the per-hop routing commands.
	var nextNode *commands.NextNodeHop
	var surbReply *commands.SURBReply

	// There is always 1 or 2 commands in the current
	// Katzenpost mixnet usage of the Sphinx packet format.
	cmds := make([]commands.RoutingCommand, 0, 2)
	for {
		cmd, rest, err := commands.FromBytes(cmdBuf, s.geometry)
		if err != nil {
			return nil, replayTag[:], nil, err
		} else if cmd == nil { // Terminal null command.
			if rest != nil {
				// Bug, should NEVER happen.
				return nil, replayTag[:], nil, errors.New("KEMSphinx: BUG: null cmd had rest")
			}
			break
		}

		switch c := cmd.(type) {
		case *commands.NextNodeHop:
			if nextNode != nil {
				return nil, replayTag[:], nil, errors.New("KEMSphinx: invalid packet, > 1 next_node")
			}
			nextNode = c
		case *commands.SURBReply:
			if surbReply != nil {
				return nil, replayTag[:], nil, errors.New("KEMSphinx: invalid packet, > 1 surb_reply")
			}
			surbReply = c
		default:
		}

		cmds = append(cmds, cmd)
		cmdBuf = rest
	}

	// Decrypt the Sphinx Packet Payload.
	payload := pkt[payloadOff:]
	if len(payload) > 0 {
		payload = crypto.SPRPDecrypt(&keys.PayloadEncryption, &keys.HeaderEncryptionIV, payload)
	}

	// Transform the packet for forwarding to the next mix, iff the
	// routing commands vector included a NextNodeHopCommand.
	if nextNode != nil {
		copy(pkt[geOff:riOff], kemCiphertext)
		copy(pkt[riOff:macOff], newRoutingInfo)
		copy(pkt[macOff:payloadOff], nextNode.MAC[:])
		if len(payload) > 0 {
			copy(pkt[payloadOff:], payload)
		}
		payload = nil
	} else {
		if len(payload) < s.geometry.PayloadTagLength {
			return nil, replayTag[:], nil, errTruncatedPayload
		}
		// Validate the payload tag, iff this is not a SURB reply.
		if surbReply == nil {
			if !utils.CtIsZero(payload[:s.geometry.PayloadTagLength]) {
				return nil, replayTag[:], nil, errInvalidTag
			}
			payload = payload[s.geometry.PayloadTagLength:]
		}
	}

	return payload, replayTag[:], cmds, nil
}
