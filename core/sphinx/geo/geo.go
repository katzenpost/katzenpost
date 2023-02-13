package geo

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/cloudflare/circl/kem"
	kemschemes "github.com/cloudflare/circl/kem/schemes"
	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/crypto/nike/schemes"
	"github.com/katzenpost/katzenpost/core/sphinx/internal/crypto"
)

const (
	NodeIDLength      = 32
	RecipientIDLength = 32
	SURBIDLength      = 16
	surbReplyLength   = 1 + SURBIDLength

	// sphinxPlaintextHeaderLength is the length of a BlockSphinxPlaintext
	// in bytes.
	sphinxPlaintextHeaderLength = 1 + 1

	adLength = 2

	// payloadTagLength is the length of the Sphinx packet payload SPRP tag.
	payloadTagLength = 32
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

	// PerHopRoutingInfoLength is the length of the per hop routing info.
	PerHopRoutingInfoLength int

	// SURBLength is the length of SURB.
	SURBLength int

	// SphinxPlaintextHeaderLength is the length of the plaintext header.
	SphinxPlaintextHeaderLength int

	// PayloadTagLength is the length of the payload tag.
	PayloadTagLength int

	// ForwardPayloadLength is the size of the payload.
	ForwardPayloadLength int

	// UserForwardPayloadLength is the size of the usable payload.
	UserForwardPayloadLength int

	// SURBIDLength is the length of a SURB ID.
	SURBIDLength int

	// RecipientIDLength is the recipient identifier length in bytes.
	RecipientIDLength int

	// NodeIDLength is the node identifier length in bytes.
	NodeIDLength int

	// NextNodeHopLength is derived off the largest routing info
	// block that we expect to encounter. Everything else just has a
	// NextNodeHop + NodeDelay, or a Recipient, both cases which are
	// shorter.
	NextNodeHopLength int

	// SPRPKeyMaterialLength is the length of the SPRP key.
	SPRPKeyMaterialLength int

	// NIKEName is the name of the NIKE scheme used by the mixnet's Sphinx packet.
	// NIKEName and KEMName are mutually exclusive.
	NIKEName string

	// KEMName is the name of the KEM scheme used by the mixnet's Sphinx packet.
	// NIKEName and KEMName are mutually exclusive.
	KEMName string
}

func (g *Geometry) Scheme() (nike.Scheme, kem.Scheme) {
	s := schemes.ByName(g.NIKEName)
	k := kemschemes.ByName(g.KEMName)
	if s == nil && k == nil {
		panic("failed to get a scheme")
	}
	return s, k
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

func (g *Geometry) Display() string {
	buf := new(bytes.Buffer)
	encoder := toml.NewEncoder(buf)
	err := encoder.Encode(g)
	if err != nil {
		panic(err)
	}
	return string(buf.Bytes())
}

type geometryFactory struct {
	nike                        nike.Scheme
	kem                         kem.Scheme
	nrHops                      int
	forwardPayloadLength        int
	sprpKeyMaterialLength       int
	sphinxPlaintextHeaderLength int
	nextNodeHopLength           int
}

func (f *geometryFactory) perHopRoutingInfoLength() int {
	if f.nike == nil { // KEM
		return f.nextNodeHopLength + surbReplyLength + f.kem.CiphertextSize()
	} else { // NIKE
		// This is derived off the largest routing info block that we expect to
		// encounter.  Everything else just has a NextNodeHop + NodeDelay, or a
		// Recipient, both cases which are shorter.
		return f.nextNodeHopLength + surbReplyLength
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
func (f *geometryFactory) surbLength() int {
	return f.headerLength() + NodeIDLength + f.sprpKeyMaterialLength
}

func (f *geometryFactory) deriveForwardPayloadLength(userForwardPayloadLength int) int {
	return userForwardPayloadLength + (sphinxPlaintextHeaderLength + f.surbLength())
}

func GeometryFromUserForwardPayloadLength(nike nike.Scheme, userForwardPayloadLength int, withSURB bool, nrHops int) *Geometry {
	f := &geometryFactory{
		nike:                        nike,
		nrHops:                      nrHops,
		sprpKeyMaterialLength:       crypto.SPRPKeyLength + crypto.SPRPIVLength,
		sphinxPlaintextHeaderLength: sphinxPlaintextHeaderLength,
		nextNodeHopLength:           1 + NodeIDLength + crypto.MACLength,
	}

	forwardPayloadLength := 0
	if withSURB {
		forwardPayloadLength = f.deriveForwardPayloadLength(userForwardPayloadLength)
	} else {
		forwardPayloadLength = userForwardPayloadLength
	}
	f.forwardPayloadLength = forwardPayloadLength // used in f.packetLength

	return &Geometry{
		NrHops:                      nrHops,
		HeaderLength:                f.headerLength(),
		PacketLength:                f.packetLength(),
		SURBLength:                  f.surbLength(),
		UserForwardPayloadLength:    userForwardPayloadLength,
		ForwardPayloadLength:        forwardPayloadLength,
		PayloadTagLength:            payloadTagLength,
		SphinxPlaintextHeaderLength: sphinxPlaintextHeaderLength,
		RoutingInfoLength:           f.routingInfoLength(),
		PerHopRoutingInfoLength:     f.perHopRoutingInfoLength(),
		SURBIDLength:                SURBIDLength,
		NodeIDLength:                NodeIDLength,
		RecipientIDLength:           RecipientIDLength,
		NextNodeHopLength:           1 + NodeIDLength + crypto.MACLength,
		SPRPKeyMaterialLength:       f.sprpKeyMaterialLength,
		NIKEName:                    nike.Name(),
	}
}

func KEMGeometryFromUserForwardPayloadLength(kem kem.Scheme, userForwardPayloadLength int, withSURB bool, nrHops int) *Geometry {
	f := &geometryFactory{
		kem:                         kem,
		nrHops:                      nrHops,
		sprpKeyMaterialLength:       crypto.SPRPKeyLength + crypto.SPRPIVLength,
		sphinxPlaintextHeaderLength: sphinxPlaintextHeaderLength,
		nextNodeHopLength:           1 + NodeIDLength + crypto.MACLength,
	}

	geo := &Geometry{
		NrHops:                      nrHops,
		HeaderLength:                f.headerLength(),
		PacketLength:                f.packetLength(),
		SURBLength:                  f.surbLength(),
		UserForwardPayloadLength:    userForwardPayloadLength,
		PayloadTagLength:            payloadTagLength,
		SphinxPlaintextHeaderLength: sphinxPlaintextHeaderLength,
		RoutingInfoLength:           f.routingInfoLength(),
		PerHopRoutingInfoLength:     f.perHopRoutingInfoLength(),
		SURBIDLength:                SURBIDLength,
		NodeIDLength:                NodeIDLength,
		RecipientIDLength:           RecipientIDLength,
		NextNodeHopLength:           1 + NodeIDLength + crypto.MACLength,
		SPRPKeyMaterialLength:       f.sprpKeyMaterialLength,
		KEMName:                     kem.Name(),
	}

	if withSURB {
		geo.ForwardPayloadLength = f.deriveForwardPayloadLength(userForwardPayloadLength)
	} else {
		geo.ForwardPayloadLength = userForwardPayloadLength
	}
	return geo
}
