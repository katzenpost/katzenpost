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

	"github.com/cloudflare/circl/kem"

	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/internal/crypto"
	"github.com/katzenpost/katzenpost/core/utils"
)

const (
	adLength = 2

	// payloadTagLength is the length of the Sphinx packet payload SPRP tag.
	payloadTagLength = 32

	// sphinxPlaintextHeaderLength is the length of a BlockSphinxPlaintext
	// in bytes.
	sphinxPlaintextHeaderLength = 1 + 1
)

var (
	v0AD = [2]byte{0x00, 0x00}

	errTruncatedPayload = errors.New("sphinx: truncated payload")
	errInvalidTag       = errors.New("sphinx: payload auth failed")

	defaultSphinx *Sphinx
)

// DefaultSphinx returns an instance of the default sphinx packet factory.
func DefaultSphinx() *Sphinx {
	return defaultSphinx
}

// DefaultGeometry returns the Sphinx geometry we are using right now.
// In the future there will be two types of Sphinx packets, classical
// and post-quantum (using CTIDH NIKE).
func DefaultGeometry() *Geometry {
	return defaultGeometry(ecdh.NewEcdhNike(rand.Reader))
}

func defaultGeometry(nike nike.Scheme) *Geometry {
	forwardPayloadLength := 2 * 1024
	nrHops := 5
	return GeometryFromForwardPayloadLength(nike, forwardPayloadLength, nrHops)
}

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

	// PerHopRoutingInfoLength is the length of the per hop routing info.
	PerHopRoutingInfoLength int

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

	// NodeIDLength is the node identifier length in bytes.
	NodeIDLength int
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

type geometryFactory struct {
	nike                 nike.Scheme
	kem                  kem.Scheme
	nrHops               int
	forwardPayloadLength int
}

func (f *geometryFactory) perHopRoutingInfoLength() int {
	if f.nike == nil { // KEM
		return commands.NextNodeHopLength + commands.SURBReplyLength + f.kem.CiphertextSize()
	} else { // NIKE
		// This is derived off the largest routing info block that we expect to
		// encounter.  Everything else just has a NextNodeHop + NodeDelay, or a
		// Recipient, both cases which are shorter.
		return commands.NextNodeHopLength + commands.SURBReplyLength
	}
}

func (f *geometryFactory) routingInfoLength() int {
	// XXX FIXME: for the KEM use case it might be possible to take one KEM ciphertext less space
	// return (f.perHopRoutingInfoLength() * f.nrHops) - f.kem.CiphertextSize()
	return (f.perHopRoutingInfoLength() * f.nrHops)
}

func (f *geometryFactory) headerLength() int {
	if f.nike == nil && f.kem == nil {
		panic("nike and kem can't both be nil")
	}
	if f.nike != nil && f.kem != nil {
		panic("nike and kem can't both be set")
	}

	if f.nike != nil {
		// NIKE
		return adLength + f.nike.PublicKeySize() + f.routingInfoLength() + crypto.MACLength
	}
	// KEM
	return adLength + f.kem.CiphertextSize() + f.routingInfoLength() + crypto.MACLength
}

// PacketLength returns the length of a Sphinx Packet in bytes.
func (f *geometryFactory) packetLength() int {
	return f.headerLength() + payloadTagLength + f.forwardPayloadLength
}

// surbLength returns the length of a Sphinx SURB in bytes.
// If the X25519 ECDH NIKE is used then the size is 556 bytes.
func (f *geometryFactory) surbLength() int {
	return f.headerLength() + constants.NodeIDLength + sprpKeyMaterialLength
}

// UserForwardPayloadLength returns the length of user portion of the forward
// payload.  The End to End spec calls this `PAYLOAD_LENGTH` but this is
// somewhat shorter than the `PAYLOAD_LENGTH` as defined in the Sphinx
// spec.
func (f *geometryFactory) userForwardPayloadLength() int {
	return f.forwardPayloadLength - (sphinxPlaintextHeaderLength + f.surbLength())
}

func (f *geometryFactory) deriveForwardPayloadLength(userForwardPayloadLength int) int {
	return userForwardPayloadLength + (sphinxPlaintextHeaderLength + f.surbLength())
}

func GeometryFromUserForwardPayloadLength(nike nike.Scheme, userForwardPayloadLength int, withSURB bool, nrHops int) *Geometry {
	f := &geometryFactory{
		nike:   nike,
		nrHops: nrHops,
	}

	forwardPayloadLength := 0
	if withSURB {
		forwardPayloadLength = f.deriveForwardPayloadLength(userForwardPayloadLength)
	} else {
		forwardPayloadLength = userForwardPayloadLength
	}
	f.forwardPayloadLength = forwardPayloadLength // used in f.packetLength
	geo := &Geometry{
		NrHops:                      nrHops,
		HeaderLength:                f.headerLength(),
		PacketLength:                f.packetLength(),
		SURBLength:                  f.surbLength(),
		UserForwardPayloadLength:    userForwardPayloadLength,
		ForwardPayloadLength:        forwardPayloadLength,
		PayloadTagLength:            payloadTagLength,
		SphinxPlaintextHeaderLength: sphinxPlaintextHeaderLength,
		SURBIDLength:                constants.SURBIDLength,
		RoutingInfoLength:           f.routingInfoLength(),
		PerHopRoutingInfoLength:     f.perHopRoutingInfoLength(),
	}

	return geo
}

func GeometryFromForwardPayloadLength(nike nike.Scheme, forwardPayloadLength, nrHops int) *Geometry {
	f := &geometryFactory{
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
		PayloadTagLength:            payloadTagLength,
		SphinxPlaintextHeaderLength: sphinxPlaintextHeaderLength,
		SURBIDLength:                constants.SURBIDLength,
		RoutingInfoLength:           f.routingInfoLength(),
		PerHopRoutingInfoLength:     f.perHopRoutingInfoLength(),
	}
}

// Sphinx is a modular implementation of the Sphinx cryptographic packet
// format that has a pluggable NIKE, non-interactive key exchange.
type Sphinx struct {
	nike     nike.Scheme
	kem      kem.Scheme
	geometry *Geometry
}

// NewSphinx creates a new instance of Sphinx.
func NewSphinx(n nike.Scheme, geometry *Geometry) *Sphinx {
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
	ID            [constants.NodeIDLength]byte
	NIKEPublicKey nike.PublicKey
	KEMPublicKey  kem.PublicKey
	Commands      []commands.RoutingCommand
}

type sprpKey struct {
	key [crypto.SPRPKeyLength]byte
	iv  [crypto.SPRPIVLength]byte
}

func (k *sprpKey) Reset() {
	utils.ExplicitBzero(k.key[:])
	utils.ExplicitBzero(k.iv[:])
}

func (s *Sphinx) commandsToBytes(cmds []commands.RoutingCommand, isTerminal bool) ([]byte, error) {
	b := make([]byte, 0, s.geometry.PerHopRoutingInfoLength)
	for _, v := range cmds {
		// NextNodeHop is generated by the header creation process.
		if _, isNextNodeHop := v.(*commands.NextNodeHop); isNextNodeHop {
			return nil, errors.New("sphinx: invalid commands, NextNodeHop")
		}
		b = v.ToBytes(b)
	}
	if len(b) > s.geometry.PerHopRoutingInfoLength {
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
	clientPublicKey, clientPrivateKey, err := s.nike.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	defer clientPrivateKey.Reset()
	defer clientPublicKey.Reset()

	groupElements := make([]nike.PublicKey, s.geometry.NrHops)
	keys := make([]*crypto.PacketKeys, s.geometry.NrHops)

	sharedSecret := s.nike.DeriveSecret(clientPrivateKey, path[0].NIKEPublicKey)
	defer utils.ExplicitBzero(sharedSecret)

	keys[0] = crypto.KDF(sharedSecret, s.nike.PrivateKeySize(), s.nike)
	defer keys[0].Reset()

	groupElements[0], err = s.nike.UnmarshalBinaryPublicKey(clientPublicKey.Bytes())
	if err != nil {
		panic(err)
	}

	for i := 1; i < nrHops; i++ {
		sharedSecret = s.nike.DeriveSecret(clientPrivateKey, path[i].NIKEPublicKey)
		for j := 0; j < i; j++ {
			pubkey := s.nike.NewEmptyPublicKey()
			err = pubkey.FromBytes(sharedSecret)
			if err != nil {
				panic(err)
			}

			blinded := s.nike.Blind(pubkey, keys[j].BlindingFactor)
			sharedSecret = blinded.Bytes()
		}
		keys[i] = crypto.KDF(sharedSecret, s.nike.PrivateKeySize(), s.nike)
		defer keys[i].Reset()

		clientPublicKey.Blind(keys[i-1].BlindingFactor)
		groupElements[i], err = s.nike.UnmarshalBinaryPublicKey(clientPublicKey.Bytes())
		if err != nil {
			panic(err)
		}
	}

	// Derive the routing_information keystream and encrypted padding for each
	// hop.
	riKeyStream := make([][]byte, s.geometry.NrHops)
	riPadding := make([][]byte, s.geometry.NrHops)

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
			return nil, nil, err
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

	var sharedSecret []byte
	defer utils.ExplicitBzero(sharedSecret)

	// Calculate the hop's shared secret, and replay_tag.
	groupElement, err := s.nike.UnmarshalBinaryPublicKey(pkt[geOff:riOff])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("sphinx: failed to unmarshal group element: %s", err)
	}
	sharedSecret = s.nike.DeriveSecret(privKey, groupElement)

	replayTag := crypto.Hash(groupElement.Bytes())

	// Derive the various keys required for packet processing.
	keys := crypto.KDF(sharedSecret, s.nike.PrivateKeySize(), s.nike)
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
	b := make([]byte, s.geometry.RoutingInfoLength+s.geometry.PerHopRoutingInfoLength)
	copy(b[:s.geometry.RoutingInfoLength], pkt[riOff:riOff+s.geometry.RoutingInfoLength])
	stream := crypto.NewStream(&keys.HeaderEncryption, &keys.HeaderEncryptionIV)
	defer stream.Reset()
	stream.XORKeyStream(b[:], b[:])

	newRoutingInfo := b[s.geometry.PerHopRoutingInfoLength:]
	cmdBuf := b[:s.geometry.PerHopRoutingInfoLength]

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

func xorBytes(dst, a, b []byte) {
	if len(a) != len(b) || len(a) != len(dst) {
		panic(fmt.Sprintf("sphinx: BUG: xorBytes called with mismatched buffer sizes, got 'len(a)' %d and 'len(b)' %d", len(a), len(b)))
	}

	// TODO: If this shows up in the profiles, vectorize it.
	for i, v := range a {
		dst[i] = v ^ b[i]
	}
}

func init() {
	nike := ecdh.NewEcdhNike(rand.Reader)
	geo := defaultGeometry(nike)
	defaultSphinx = NewSphinx(nike, geo)
}
