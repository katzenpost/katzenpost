package packet_factory

import (
	"fmt"
	"time"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"

	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	sphinxPath "github.com/katzenpost/katzenpost/core/sphinx/path"
)

// PacketFactory is used to compose Sphinx packets.
type PacketFactory struct {
	pathFactory *sphinxPath.PathFactory
	geo         *geo.Geometry
	sphinx      *sphinx.Sphinx
}

// PacketFactoryOption is an option to the Sphinx packet factory.
type PacketFactoryOption func(*PacketFactory)

// WithPathFactory is used to set the path factory.
func WithPathFactory(pathFactory *sphinxPath.PathFactory) PacketFactoryOption {
	return func(PacketFactory *PacketFactory) {
		PacketFactory.pathFactory = pathFactory
	}
}

func NewPacketFactory(geo *geo.Geometry, opts ...PacketFactoryOption) *PacketFactory {
	s, err := sphinx.FromGeometry(geo)
	if err != nil {
		panic(err)
	}
	factory := &PacketFactory{
		pathFactory: sphinxPath.NewPathFactory(),
		geo:         geo,
		sphinx:      s,
	}
	for _, opt := range opts {
		opt(factory)
	}
	return factory
}

func (p *PacketFactory) ComposePacket(
	doc *pki.Document,
	srcId []byte,
	srcMix *[32]byte,
	dstId []byte,
	dstMix *[32]byte,
	surbID *[constants.SURBIDLength]byte,
	message []byte) (packet []byte, surbKey []byte, rtt time.Duration, err error) {

	if len(dstId) > constants.RecipientIDLength {
		return nil, nil, 0, fmt.Errorf("minclient: invalid recipient: '%v'", dstId)
	}
	if len(message) > p.geo.UserForwardPayloadLength {
		return nil, nil, 0, fmt.Errorf("minclient: invalid ciphertext size: %v", len(message))
	}

	payload := make([]byte, p.geo.UserForwardPayloadLength)
	payload = append(payload, message...)

	for {
		unixTime := time.Now().Unix()
		_, _, budget := epochtime.FromUnix(unixTime)
		start := time.Now()

		// Select the forward path.
		now := time.Unix(unixTime, 0)

		fwdPath, then, err := p.pathFactory.ComposePath(
			p.geo,
			doc,
			srcMix,
			dstId,
			dstMix,
			surbID,
			now,
			true)
		if err != nil {
			return nil, nil, 0, err
		}

		revPath := make([]*sphinxPath.PathHop, 0)
		if surbID != nil {
			revPath, then, err = p.pathFactory.ComposePath(
				p.geo,
				doc,
				dstMix,
				srcId,
				srcMix,
				surbID,
				then,
				false)
			if err != nil {
				return nil, nil, 0, err
			}
		}

		// If the path selection process ends up straddling an epoch
		// transition, then redo the path selection.
		if time.Since(start) > budget {
			continue
		}

		// It is possible, but unlikely that a series of delays exceeding
		// the PKI publication imposted limitations will be selected.  When
		// that happens, the path selection must be redone.
		if then.Sub(now) < epochtime.Period*2 {
			if surbID != nil {
				payload := make([]byte, 2, 2+p.geo.SURBLength+len(message))
				payload[0] = 1 // Packet has a SURB.
				surb, k, err := p.sphinx.NewSURB(rand.Reader, revPath)
				if err != nil {
					return nil, nil, 0, err
				}
				payload = append(payload, surb...)
				payload = append(payload, message...)

				pkt, err := p.sphinx.NewPacket(rand.Reader, fwdPath, payload)
				if err != nil {
					return nil, nil, 0, err
				}
				return pkt, k, then.Sub(now), err
			} else {
				pkt, err := p.sphinx.NewPacket(rand.Reader, fwdPath, payload)
				if err != nil {
					return nil, nil, 0, err
				}
				return pkt, nil, then.Sub(now), nil
			}
		}
	}
}
