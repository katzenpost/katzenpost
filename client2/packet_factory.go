package client2

import (
	"errors"
	"fmt"
	mRand "math/rand"
	"time"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/path"
)

// PathFactory is used to compose Sphinx packet paths.
type PathFactory interface {

	// ComposePath is used to compose a Sphinx packet path. Returns
	// path and round trip time or an error.
	ComposePath(
		doc *pki.Document,
		srcMix *[32]byte,
		dstId []byte,
		dstMix *[32]byte,
		surbID *[constants.SURBIDLength]byte,
		baseTime time.Time,
		isForward bool) (path []*sphinx.PathHop, rtt time.Time, err error)
}

// PacketFactory is used to compose Sphinx packets.
type PacketFactory interface {

	// ComposePacket is used to compose Sphinx packets. Returns
	// a Sphinx packet, a surbKey and round trip time or an error.
	ComposePacket(
		doc *pki.Document,
		srcId []byte,
		srcMix *[32]byte,
		dstId []byte,
		dstMix *[32]byte,
		surbID *[constants.SURBIDLength]byte,
		message []byte) (packet []byte, surbKey []byte, rtt time.Duration, err error)
}

type packetFactory struct {
	pathFactory PathFactory
	geo         *sphinx.Geometry
	sphinx      *sphinx.Sphinx
}

// PacketFactoryOption is an option to the Sphinx packet factory.
type PacketFactoryOption func(*packetFactory)

// WithPathFactory is used to set the path factory.
func WithPathFactory(pathFactory PathFactory) PacketFactoryOption {
	return func(packetFactory *packetFactory) {
		packetFactory.pathFactory = pathFactory
	}
}

func newPacketFactory(opts ...PacketFactoryOption) *packetFactory {
	factory := &packetFactory{
		pathFactory: new(defaultPathFactory),
		geo:         sphinx.DefaultGeometry(),
	}
	for _, opt := range opts {
		opt(factory)
	}
	return factory
}

func (p *packetFactory) ComposePacket(
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
	if len(message) != p.geo.UserForwardPayloadLength {
		return nil, nil, 0, fmt.Errorf("minclient: invalid ciphertext size: %v", len(message))
	}

	// Wrap the ciphertext in a BlockSphinxCiphertext.
	payload := make([]byte, 2+p.geo.SURBLength, 2+p.geo.SURBLength+len(message))
	payload = append(payload, message...)

	for {
		unixTime := time.Now().Unix()
		_, _, budget := epochtime.FromUnix(unixTime)
		start := time.Now()

		// Select the forward path.
		now := time.Unix(unixTime, 0)

		fwdPath, then, err := p.pathFactory.ComposePath(
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

		revPath := make([]*sphinx.PathHop, 0)
		if surbID != nil {
			revPath, then, err = p.pathFactory.ComposePath(
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

type defaultPathFactory struct {
	rng *mRand.Rand
}

func newDefaultPathFactory() *defaultPathFactory {
	return &defaultPathFactory{
		rng: rand.NewMath(),
	}
}

// ComposePath is used to compose a Sphinx packet path. Returns
// path and round trip time or an error.
func (d *defaultPathFactory) ComposePath(
	doc *pki.Document,
	srcMix *[32]byte,
	dstId []byte,
	dstMix *[32]byte,
	surbID *[constants.SURBIDLength]byte,
	baseTime time.Time,
	isForward bool) (outputPath []*sphinx.PathHop, rtt time.Time, err error) {

	src, err := doc.GetProviderByKeyHash(srcMix)
	if err != nil {
		return nil, time.Time{}, errors.New("failed to find entry mix in pki doc")
	}
	dst, err := doc.GetProviderByKeyHash(dstMix)
	if err != nil {
		return nil, time.Time{}, errors.New("failed to find service mix in pki doc")
	}
	return path.New(d.rng, doc, dstId, src, dst, surbID, baseTime, true, isForward)
}
