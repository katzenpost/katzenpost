// sphinx.go - Sphinx Packet Format.
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

// Package sphinx implements the Katzenpost parameterized Sphinx Packet Format.
package sphinx

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/internal/crypto"
	"github.com/katzenpost/katzenpost/core/utils"
)

const (
	// This is derived off the largest routing info block that we expect to
	// encounter.  Everything else just has a NextNodeHop + NodeDelay, or a
	// Recipient, both cases which are shorter.
	perHopRoutingInfoLength = commands.RecipientLength + commands.SURBReplyLength
	adLength                = 2

	// PayloadTagLength is the length of the Sphinx packet payload SPRP tag.
	PayloadTagLength = 16

	// SphinxPlaintextHeaderLength is the length of a BlockSphinxPlaintext
	// in bytes.
	SphinxPlaintextHeaderLength = 1 + 1

	// NodeIDLength is the node identifier length in bytes.
	NodeIDLength = 32

	// RecipientIDLength is the recipient identifier length in bytes.
	RecipientIDLength = 64

	// SURBIDLength is the SURB identifier length in bytes.
	SURBIDLength = 16
)

var (
	v0AD      = [2]byte{0x00, 0x00}
	zeroBytes = [perHopRoutingInfoLength]byte{}

	errTruncatedPayload = errors.New("sphinx: truncated payload")
	errInvalidTag       = errors.New("sphinx: payload auth failed")
)

// Geometry describes the geometry of a Sphinx packet.
type Geometry struct {

	// PacketLength is the length of a packet.
	PacketLength int

	// NrHops is the number of hops, this indicates the size
	// of the Sphinx packet header.
	NrHops int

	// HeaderLength is the length of the Sphinx packet header in bytes.
	HeaderLength int

	// RoutingInfoLength is the length of the routing info portion of the header.
	RoutingInfoLength int

	// SURBLength is the length of SURB.
	SURBLength int

	// SphinxPlaintextHeaderLength is the length of the plaintext header.
	SphinxPlaintextHeaderLength int

	// SURBIDLength is the length of a SURB ID.
	SURBIDLength int

	// PayloadTagLength is the length of the payload tag.
	PayloadTagLength int

	// ForwardPayloadLength is the size of the payload.
	ForwardPayloadLength int

	// UserForwardPayloadLength is the size of the usable payload.
	UserForwardPayloadLength int
}

func (g *Geometry) String() string {
	var b strings.Builder
	b.WriteString("sphinx_packet_geometry:\n")
	b.WriteString(fmt.Sprintf("packet size: %d\n", g.PacketLength))
	b.WriteString(fmt.Sprintf("number of hops: %d\n", g.NrHops))
	b.WriteString(fmt.Sprintf("header size: %d\n", g.HeaderLength))
	b.WriteString(fmt.Sprintf("forward payload size: %d\n", g.ForwardPayloadLength))
	b.WriteString(fmt.Sprintf("user forward payload size: %d\n", g.UserForwardPayloadLength))
	b.WriteString(fmt.Sprintf("payload tag size: %d\n", g.PayloadTagLength))
	b.WriteString(fmt.Sprintf("routing info size: %d\n", g.RoutingInfoLength))
	b.WriteString(fmt.Sprintf("surb size: %d\n", g.SURBLength))
	b.WriteString(fmt.Sprintf("sphinx plaintext header size: %d\n", g.SphinxPlaintextHeaderLength))
	return b.String()
}

type GeometryFactory struct {
	nike                 nike.Nike
	nrHops               int
	forwardPayloadLength int
}

func (f *GeometryFactory) routingInfoLength() int {
	return perHopRoutingInfoLength * f.nrHops
}

func (f *GeometryFactory) headerLength() int {
	// 460 bytes with a 32byte public key
	return adLength + f.nike.PublicKeySize() + f.routingInfoLength() + crypto.MACLength
}

// PacketLength returns the length of a Sphinx Packet in bytes.
func (f *GeometryFactory) packetLength() int {
	return f.headerLength() + PayloadTagLength + f.forwardPayloadLength
}

// surbLength returns the length of a Sphinx SURB in bytes.
// If the X25519 ECDH NIKE is used then the size is 556 bytes.
func (f *GeometryFactory) surbLength() int {
	return f.headerLength() + constants.NodeIDLength + sprpKeyMaterialLength
}

// UserForwardPayloadLength returns the length of user portion of the forward
// payload.  The End to End spec calls this `PAYLOAD_LENGTH` but this is
// somewhat shorter than the `PAYLOAD_LENGTH` as defined in the Sphinx
// spec.
func (f *GeometryFactory) userForwardPayloadLength() int {
	return f.forwardPayloadLength - (SphinxPlaintextHeaderLength + f.surbLength())
}

func (f *GeometryFactory) deriveForwardPayloadLength(userForwardPayloadLength int) int {
	return userForwardPayloadLength + (SphinxPlaintextHeaderLength + f.surbLength())
}

func GeometryFromUserForwardPayloadLength(nike nike.Nike, userForwardPayloadLength int, withSURB bool, nrHops int) *Geometry {
	f := &GeometryFactory{
		nike:   nike,
		nrHops: nrHops,
	}
	geo := &Geometry{
		NrHops:                      nrHops,
		HeaderLength:                f.headerLength(),
		PacketLength:                f.packetLength(),
		SURBLength:                  f.surbLength(),
		UserForwardPayloadLength:    userForwardPayloadLength,
		PayloadTagLength:            PayloadTagLength,
		SphinxPlaintextHeaderLength: SphinxPlaintextHeaderLength,
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

func GeometryFromForwardPayloadLength(nike nike.Nike, forwardPayloadLength, nrHops int) *Geometry {
	f := &GeometryFactory{
		nike:                 nike,
		nrHops:               nrHops,
		forwardPayloadLength: forwardPayloadLength,
	}
	return &Geometry{
		NrHops:                      nrHops,
		HeaderLength:                f.headerLength(),
		PacketLength:                f.packetLength(),
		SURBLength:                  f.surbLength(),
		UserForwardPayloadLength:    f.userForwardPayloadLength(),
		ForwardPayloadLength:        f.forwardPayloadLength,
		PayloadTagLength:            PayloadTagLength,
		SphinxPlaintextHeaderLength: SphinxPlaintextHeaderLength,
		SURBIDLength:                constants.SURBIDLength,
		RoutingInfoLength:           f.routingInfoLength(),
	}
}

// Sphinx is a modular implementation of the Sphinx cryptographic packet
// format that has a pluggable NIKE, non-interactive key exchange.
type Sphinx struct {
	nike     nike.Nike
	geometry *Geometry
}

// NewSphinx creates a new instance of Sphinx.
func NewSphinx(n nike.Nike, geometry *Geometry) *Sphinx {
	s := &Sphinx{
		nike:     n,
		geometry: geometry,
	}
	return s
}

// Geometry returns the Sphinx packet geometry.
func (s *Sphinx) Geometry() *Geometry {
	return s.geometry
}

// PathHop describes a hop that a Sphinx Packet will traverse, along with
// all of the per-hop Commands (excluding NextNodeHop).
type PathHop struct {
	ID        [constants.NodeIDLength]byte
	PublicKey nike.PublicKey
	Commands  []commands.RoutingCommand
}

type sprpKey struct {
	key [crypto.SPRPKeyLength]byte
	iv  [crypto.SPRPIVLength]byte
}

func (k *sprpKey) Reset() {
	utils.ExplicitBzero(k.key[:])
	utils.ExplicitBzero(k.iv[:])
}

func commandsToBytes(cmds []commands.RoutingCommand, isTerminal bool) ([]byte, error) {
	b := make([]byte, 0, perHopRoutingInfoLength)
	for _, v := range cmds {
		// NextNodeHop is generated by the header creation process.
		if _, isNextNodeHop := v.(*commands.NextNodeHop); isNextNodeHop {
			return nil, errors.New("sphinx: invalid commands, NextNodeHop")
		}
		b = v.ToBytes(b)
	}
	if len(b) > perHopRoutingInfoLength {
		return nil, errors.New("sphinx: invalid commands, oversized serialized block")
	}
	if !isTerminal && cap(b)-len(b) < commands.NextNodeHopLength {
		return nil, errors.New("sphinx: invalid commands, insufficient remaining capacity")
	}

	return b, nil
}

func (s *Sphinx) createHeader(r io.Reader, path []*PathHop) ([]byte, []*sprpKey, error) {
	nrHops := len(path)
	if nrHops > s.geometry.NrHops {
		return nil, nil, errors.New("sphinx: invalid path")
	}

	// Derive the key material for each hop.
	clientPrivateKey, clientPublicKey := s.nike.NewKeypair()
	defer clientPrivateKey.Reset()
	defer clientPublicKey.Reset()

	groupElements := make([]nike.PublicKey, s.geometry.NrHops)
	keys := make([]*crypto.PacketKeys, s.geometry.NrHops)

	sharedSecret := s.nike.DeriveSecret(clientPrivateKey, path[0].PublicKey)
	defer utils.ExplicitBzero(sharedSecret)

	keys[0] = crypto.KDF(sharedSecret, s.nike.PrivateKeySize())
	defer keys[0].Reset()

	groupElements[0] = s.nike.NewEmptyPublicKey()
	err := groupElements[0].FromBytes(clientPublicKey.Bytes())
	if err != nil {
		panic(err)
	}

	for i := 1; i < nrHops; i++ {
		sharedSecret = s.nike.DeriveSecret(clientPrivateKey, path[i].PublicKey)
		for j := 0; j < i; j++ {
			sharedSecret = s.nike.Blind(sharedSecret, keys[j].BlindingFactor)
		}
		keys[i] = crypto.KDF(sharedSecret, s.nike.PrivateKeySize())
		defer keys[i].Reset()
		clientPublicKey.Blind(keys[i-1].BlindingFactor)
		groupElements[i] = s.nike.NewEmptyPublicKey()
		err = groupElements[i].FromBytes(clientPublicKey.Bytes())
		if err != nil {
			panic(err)
		}
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

	// Create the routing_information block.
	var mac []byte
	var routingInfo []byte
	if skippedHops := s.geometry.NrHops - nrHops; skippedHops > 0 {
		routingInfo = make([]byte, skippedHops*perHopRoutingInfoLength)
		_, err := io.ReadFull(rand.Reader, routingInfo)
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
		}
		if padLen := perHopRoutingInfoLength - len(riFragment); padLen > 0 {
			riFragment = append(riFragment, zeroBytes[:padLen]...)
		}

		routingInfo = append(riFragment, routingInfo...) // Prepend
		xorBytes(routingInfo, routingInfo, riKeyStream[i])

		m := crypto.NewMAC(&keys[i].HeaderMAC)
		defer m.Reset()
		m.Write(v0AD[:])
		m.Write(groupElements[i].Bytes())
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
	hdr = append(hdr, groupElements[0].Bytes()...)
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

// NewPacket creates a forward Sphinx packet with the provided path and
// payload, using the provided entropy source.
func (s *Sphinx) NewPacket(r io.Reader, path []*PathHop, payload []byte) ([]byte, error) {
	if len(payload) != s.geometry.ForwardPayloadLength {
		return nil, fmt.Errorf("invalid payload length: %d, expected %d", len(payload), s.geometry.ForwardPayloadLength)
	}

	hdr, sprpKeys, err := s.createHeader(r, path)
	if err != nil {
		return nil, err
	}
	for _, v := range sprpKeys {
		defer v.Reset()
	}

	// Assemble the packet.
	pkt := make([]byte, 0, len(hdr)+PayloadTagLength+len(payload))
	pkt = append(pkt, hdr...)
	pkt = append(pkt, zeroBytes[:PayloadTagLength]...)
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

// Unwrap unwraps the provided Sphinx packet pkt in-place, using the provided
// NIKE private key, and returns the payload (if applicable), replay tag, and
// routing info command vector.
func (s *Sphinx) Unwrap(privKey nike.PrivateKey, pkt []byte) ([]byte, []byte, []commands.RoutingCommand, error) {
	var (
		geOff      = 2
		riOff      = geOff + s.nike.PublicKeySize()
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

	// Calculate the hop's shared secret, and replay_tag.
	groupElement := s.nike.NewEmptyPublicKey()
	var sharedSecret []byte
	defer utils.ExplicitBzero(sharedSecret)

	err := groupElement.FromBytes(pkt[geOff:riOff])
	if err != nil {
		panic(err)
	}
	sharedSecret = s.nike.DeriveSecret(privKey, groupElement)

	replayTag := crypto.Hash(groupElement.Bytes())

	// Derive the various keys required for packet processing.
	keys := crypto.KDF(sharedSecret, s.nike.PrivateKeySize())
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
		groupElement.Blind(keys.BlindingFactor)
		copy(pkt[geOff:riOff], groupElement.Bytes()[:])
		copy(pkt[riOff:macOff], newRoutingInfo)
		copy(pkt[macOff:payloadOff], nextNode.MAC[:])
		if len(payload) > 0 {
			copy(pkt[payloadOff:], payload)
		}
		payload = nil
	} else {
		if len(payload) < PayloadTagLength {
			return nil, replayTag[:], nil, errTruncatedPayload
		}
		// Validate the payload tag, iff this is not a SURB reply.
		if surbReply == nil {
			if !utils.CtIsZero(payload[:PayloadTagLength]) {
				return nil, replayTag[:], nil, errInvalidTag
			}
			payload = payload[PayloadTagLength:]
		}
	}

	return payload, replayTag[:], cmds, nil
}

func xorBytes(dst, a, b []byte) {
	if len(a) != len(b) || len(a) != len(dst) {
		panic(fmt.Sprintf("sphinx: BUG: xorBytes called with mismatched buffer sizes, got %d and %d", len(a), len(b)))
	}

	// TODO: If this shows up in the profiles, vectorize it.
	for i, v := range a {
		dst[i] = v ^ b[i]
	}
}
