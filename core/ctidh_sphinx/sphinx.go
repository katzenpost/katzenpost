// sphinx.go - Sphinx Packet Format using the CTIDH non-interactive key exchange.
// Copyright (C) 2022  David Stainton and Yawning Angel.
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

// Package ctidh_sphinx implements the Katzenpost parameterized Sphinx Packet Format
// with CTIDH, a non-interactive key exchange instead of X25519.
package ctidh_sphinx

import (
	"crypto/subtle"
	"errors"
	"io"

	ctidh "git.xx.network/elixxir/ctidh_cgo"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/utils"

	"github.com/katzenpost/katzenpost/core/ctidh_sphinx/commands"
	"github.com/katzenpost/katzenpost/core/ctidh_sphinx/constants"
	"github.com/katzenpost/katzenpost/core/ctidh_sphinx/internal/crypto"
)

const (
	// This is derived off the largest routing info block that we expect to
	// encounter.  Everything else just has a NextNodeHop + NodeDelay, or a
	// Recipient, both cases which are shorter.
	perHopRoutingInfoLength = commands.RecipientLength + commands.SURBReplyLength

	routingInfoLength = perHopRoutingInfoLength * constants.NrHops
	adLength          = 2

	// PayloadTagLength is the length of the Sphinx packet payload SPRP tag.
	PayloadTagLength = 16
)

var (
	// HeaderLength is the length of a Sphinx packet header in bytes.
	HeaderLength = adLength + ctidh.PublicKeySize + routingInfoLength + crypto.MACLength // 460 bytes.

	v0AD      = [2]byte{0x00, 0x00}
	zeroBytes = [perHopRoutingInfoLength]byte{}

	errTruncatedPayload = errors.New("sphinx: truncated payload")
	errInvalidTag       = errors.New("sphinx: payload auth failed")
)

// PathHop describes a hop that a Sphinx Packet will traverse, along with
// all of the per-hop Commands (excluding NextNodeHop).
type PathHop struct {
	ID        [constants.NodeIDLength]byte
	PublicKey *ctidh.PublicKey
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

func createHeader(r io.Reader, path []*PathHop) ([]byte, []*sprpKey, error) {
	nrHops := len(path)
	if nrHops > constants.NrHops {
		return nil, nil, errors.New("sphinx: invalid path")
	}

	// Derive the key material for each hop.
	clientPrivateKey, clientPublicKey := ctidh.GenerateKeyPair()
	defer clientPrivateKey.Reset()
	defer clientPublicKey.Reset()

	var groupElements [constants.NrHops]ctidh.PublicKey
	var keys [constants.NrHops]*crypto.PacketKeys

	sharedSecret := ctidh.DeriveSecret(clientPrivateKey, path[0].PublicKey)
	defer utils.ExplicitBzero(sharedSecret)

	keys[0] = crypto.KDF(sharedSecret)
	defer keys[0].Reset()
	err := groupElements[0].FromBytes(clientPublicKey.Bytes())
	if err != nil {
		panic(err)
	}
	for i := 1; i < nrHops; i++ {
		sharedSecret = ctidh.DeriveSecret(clientPrivateKey, path[i].PublicKey)
		for j := 0; j < i; j++ {
			sharedSecret, err = ctidh.Blind(sharedSecret, keys[j].BlindingFactor)
			if err != nil {
				panic(err)
			}
		}
		keys[i] = crypto.KDF(sharedSecret)
		defer keys[i].Reset()
		clientPublicKey.Blind(keys[i-1].BlindingFactor)
		groupElements[i].FromBytes(clientPublicKey.Bytes())
	}

	// Derive the routing_information keystream and encrypted padding for each
	// hop.
	var riKeyStream [constants.NrHops][]byte
	var riPadding [constants.NrHops][]byte

	for i := 0; i < nrHops; i++ {
		keyStream := make([]byte, routingInfoLength+perHopRoutingInfoLength)
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
	if skippedHops := constants.NrHops - nrHops; skippedHops > 0 {
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
	hdr := make([]byte, 0, HeaderLength)
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
func NewPacket(r io.Reader, path []*PathHop, payload []byte) ([]byte, error) {
	hdr, sprpKeys, err := createHeader(r, path)
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
// CTIDH private key, and returns the payload (if applicable), replay tag, and
// routing info command vector.
func Unwrap(privKey *ctidh.PrivateKey, pkt []byte) ([]byte, []byte, []commands.RoutingCommand, error) {
	var (
		geOff      = 2
		riOff      = geOff + crypto.GroupElementLength
		macOff     = riOff + routingInfoLength
		payloadOff = macOff + crypto.MACLength
	)

	// Do some basic sanity checking, and validate the AD.
	if len(pkt) < HeaderLength {
		return nil, nil, nil, errors.New("sphinx: invalid packet, truncated")
	}
	if subtle.ConstantTimeCompare(v0AD[:], pkt[:2]) != 1 {
		return nil, nil, nil, errors.New("sphinx: invalid packet, unknown version")
	}

	// Calculate the hop's shared secret, and replay_tag.
	var groupElement ctidh.PublicKey
	var sharedSecret []byte
	defer utils.ExplicitBzero(sharedSecret)
	groupElement.FromBytes(pkt[geOff:riOff])
	sharedSecret = ctidh.DeriveSecret(privKey, &groupElement)

	replayTag := crypto.Hash(groupElement.Bytes())

	// Derive the various keys required for packet processing.
	keys := crypto.KDF(sharedSecret)
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
	var b [routingInfoLength + perHopRoutingInfoLength]byte
	copy(b[:routingInfoLength], pkt[riOff:riOff+routingInfoLength])
	s := crypto.NewStream(&keys.HeaderEncryption, &keys.HeaderEncryptionIV)
	defer s.Reset()
	s.XORKeyStream(b[:], b[:])

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
		copy(pkt[geOff:riOff], groupElement.Bytes())
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
		panic("sphinx: BUG: xorBytes called with mismatched buffer sizes")
	}

	// TODO: If this shows up in the profiles, vectorize it.
	for i, v := range a {
		dst[i] = v ^ b[i]
	}
}
