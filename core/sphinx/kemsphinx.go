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

	"github.com/cloudflare/circl/kem"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/internal/crypto"
	"github.com/katzenpost/katzenpost/core/utils"
)

func KEMGeometryFromUserForwardPayloadLength(kem kem.Scheme, userForwardPayloadLength int, withSURB bool, nrHops int) *Geometry {
	f := &geometryFactory{
		kem:    kem,
		nrHops: nrHops,
	}
	geo := &Geometry{
		NrHops:                      nrHops,
		HeaderLength:                f.headerLength(),
		PacketLength:                f.packetLength(),
		SURBLength:                  f.surbLength(),
		UserForwardPayloadLength:    userForwardPayloadLength,
		PayloadTagLength:            payloadTagLength,
		SphinxPlaintextHeaderLength: sphinxPlaintextHeaderLength,
		SURBIDLength:                constants.SURBIDLength,
		RoutingInfoLength:           f.routingInfoLength(),
	}

	if withSURB {
		geo.ForwardPayloadLength = f.deriveForwardPayloadLength(userForwardPayloadLength)
	} else {
		geo.ForwardPayloadLength = userForwardPayloadLength
	}
	return geo
}

// NewKEMSphinx creates a new instance of KEMSphinx, the Sphinx
// nested cryptographic packet format that uses a KEM instead of a NIKE.
// This implies lots of packet over, one KEM encapsulation per hop actually.
// But since we no longer use 2400 maude modems let's rock out with
// our Hybrid Classical + PQ KEM Sphinx.
func NewKEMSphinx(k kem.Scheme, geometry *Geometry) *Sphinx {
	s := &Sphinx{
		kem:      k,
		geometry: geometry,
	}
	return s
}

func (s *Sphinx) NewKEMPacket(r io.Reader, path []*PathHop, payload []byte) ([]byte, error) {
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
3. encrypted KEM ciphtertexts, one for each additional hop
4. encrypted per routing commands
5. MAC for this hop (authenticates header fields 1-4)
*/
func (s *Sphinx) createKEMHeader(r io.Reader, path []*PathHop) ([]byte, []*sprpKey, error) {
	nrHops := len(path)
	if nrHops > s.geometry.NrHops {
		return nil, nil, errors.New("sphinx: invalid path")
	}

	// Derive the key material for each hop.

	var err error
	var sharedSecret []byte
	kemElements := make([][]byte, s.geometry.NrHops)
	keys := make([]*crypto.PacketKeys, s.geometry.NrHops)

	for i := 0; i < nrHops; i++ {
		kemElements[i], sharedSecret, err = s.kem.Encapsulate(path[i].KEMPublicKey)
		if err != nil {
			panic(err)
		}
		defer utils.ExplicitBzero(sharedSecret)

		// set privateKey size to zero 0 since
		// we don't need to generate blinding factors
		// for KEMSphinx.
		keys[i] = crypto.KDF(sharedSecret, 0)
		defer keys[i].Reset()
	}

	// Derive the routing_information keystream and encrypted padding for each
	// hop.
	riKeyStream := make([][]byte, s.geometry.NrHops)
	riPadding := make([][]byte, s.geometry.NrHops)

	for i := 0; i < nrHops; i++ {
		keyStream := make([]byte, s.geometry.RoutingInfoLength+perHopRoutingInfoLength)
		defer utils.ExplicitBzero(keyStream)

		s := crypto.NewStream(&keys[i].HeaderEncryption, &keys[i].HeaderEncryptionIV)
		s.KeyStream(keyStream)
		s.Reset()

		ksLen := len(keyStream) - (i+1)*perHopRoutingInfoLength
		riKeyStream[i] = keyStream[:ksLen]
		riPadding[i] = keyStream[ksLen:]
		if i > 0 {
			prevPadLen := len(riPadding[i-1])
			xorBytes(riPadding[i][:prevPadLen], riPadding[i][:prevPadLen], riPadding[i-1])
		}
	}

	// Create the routing_information block and the encrypted KEM block.
	var mac []byte
	var routingInfo []byte
	if skippedHops := s.geometry.NrHops - nrHops; skippedHops > 0 {
		routingInfo = make([]byte, skippedHops*perHopRoutingInfoLength)
		_, err := io.ReadFull(rand.Reader, routingInfo)
		if err != nil {
			return nil, nil, err
		}
	}

	var encryptedKEMs []byte
	if skippedHops := s.geometry.NrHops - nrHops; skippedHops > 0 {
		encryptedKEMs = make([]byte, skippedHops*s.kem.CiphertextSize())
		_, err := io.ReadFull(rand.Reader, encryptedKEMs)
		if err != nil {
			return nil, nil, err
		}
	}

	for i := nrHops - 1; i >= 0; i-- {
		isTerminal := i == nrHops-1
		riFragment, err := commandsToBytes(path[i].Commands, isTerminal)
		if err != nil {
			return nil, nil, err
		}
		if !isTerminal {
			nextCmd := &commands.NextNodeHop{}
			copy(nextCmd.ID[:], path[i+1].ID[:])
			copy(nextCmd.MAC[:], mac)
			riFragment = nextCmd.ToBytes(riFragment)
			encryptedKEMs = append(encryptedKEMs, kemElements[i+1]...)
		}
		if padLen := perHopRoutingInfoLength - len(riFragment); padLen > 0 {
			riFragment = append(riFragment, zeroBytes[:padLen]...)
		}
		routingInfo = append(riFragment, routingInfo...) // Prepend

		xorBytes(routingInfo, routingInfo, riKeyStream[i])
		xorBytes(encryptedKEMs, encryptedKEMs, riKeyStream[i])

		m := crypto.NewMAC(&keys[i].HeaderMAC)
		defer m.Reset()
		m.Write(v0AD[:])
		m.Write(kemElements[i])
		m.Write(encryptedKEMs)
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
	hdr = append(hdr, encryptedKEMs...)
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

// KEMUnwrap unwraps the provided KEMSphinx packet pkt in-place, using the provided
// KEM private key, and returns the payload (if applicable), replay tag, and
// routing info command vector.
func (s *Sphinx) KEMUnwrap(privKey kem.PrivateKey, pkt []byte) ([]byte, []byte, []commands.RoutingCommand, error) {
	var (
		geOff      = 2
		kemsOff    = geOff + s.kem.CiphertextSize()
		riOff      = kemsOff + (s.kem.CiphertextSize() * (s.geometry.NrHops - 1))
		macOff     = riOff + s.geometry.RoutingInfoLength
		payloadOff = macOff + crypto.MACLength
	)

	// Do some basic sanity checking, and validate the AD.
	if len(pkt) < s.geometry.HeaderLength {
		return nil, nil, nil, errors.New("sphinx: invalid packet, truncated")
	}
	if subtle.ConstantTimeCompare(v0AD[:], pkt[:2]) != 1 {
		return nil, nil, nil, errors.New("sphinx: invalid packet, unknown version")
	}

	var sharedSecret []byte
	defer utils.ExplicitBzero(sharedSecret)

	// Calculate the hop's shared secret, and replay_tag.

	kemCiphertext := pkt[geOff:kemsOff]
	sharedSecret, err := privKey.Scheme().Decapsulate(privKey, kemCiphertext)

	// FIXME: do we need this?
	replayTag := crypto.Hash(kemCiphertext)

	// Derive the various keys required for packet processing.
	// note we set the private key size to zero because we do not
	// derive blinding factors for KEMSphinx!
	keys := crypto.KDF(sharedSecret, 0)
	defer keys.Reset()

	// Validate the Sphinx Packet Header.
	m := crypto.NewMAC(&keys.HeaderMAC)
	defer m.Reset()
	m.Write(pkt[0:macOff])
	mac := m.Sum(nil)

	if subtle.ConstantTimeCompare(pkt[macOff:macOff+crypto.MACLength], mac) != 1 {
		return nil, replayTag[:], nil, errors.New("sphinx: invalid packet, MAC mismatch")
	}

	// Append padding to preserve length invariance, decrypt the (padded)
	// routing_info block, and extract the section for the current hop.
	b := make([]byte, s.geometry.RoutingInfoLength+perHopRoutingInfoLength)
	copy(b[:s.geometry.RoutingInfoLength], pkt[riOff:riOff+s.geometry.RoutingInfoLength])
	stream := crypto.NewStream(&keys.HeaderEncryption, &keys.HeaderEncryptionIV)
	defer stream.Reset()
	stream.XORKeyStream(b[:], b[:])

	newRoutingInfo := b[perHopRoutingInfoLength:]
	cmdBuf := b[:perHopRoutingInfoLength]

	// Parse the per-hop routing commands.
	var nextNode *commands.NextNodeHop
	var surbReply *commands.SURBReply
	cmds := make([]commands.RoutingCommand, 0, 2) // Usually 2, excluding null.
	for {
		cmd, rest, err := commands.FromBytes(cmdBuf)
		if err != nil {
			return nil, replayTag[:], nil, err
		} else if cmd == nil { // Terminal null command.
			if rest != nil {
				// Bug, should NEVER happen.
				return nil, replayTag[:], nil, errors.New("sphinx: BUG: null cmd had rest")
			}
			break
		}

		switch c := cmd.(type) {
		case *commands.NextNodeHop:
			if nextNode != nil {
				return nil, replayTag[:], nil, errors.New("sphinx: invalid packet, > 1 next_node")
			}
			nextNode = c
		case *commands.SURBReply:
			if surbReply != nil {
				return nil, replayTag[:], nil, errors.New("sphinx: invalid packet, > 1 surb_reply")
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
		copy(pkt[geOff:kemsOff], pkt[kemsOff:kemsOff+s.kem.CiphertextSize()])
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
