package geo

import (
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
)

const (
	surbReplyLength = constants.CommandTagLength + constants.SURBIDLength

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
