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

// Client manages startup, shutdow, creating new connections and reconnecting.
type Client interface {

	// ReconnectOldSession reuses the old noise protocol key to reconnect to
	// a previously selected entry mix.
	ReconnectOldSession(Session) error

	// NewSession generates a new noise protocol key and connects to a randomly
	// selected entry mix.
	NewSession() (Session, error)

	// Wait waits for the client to shut down.
	Wait()

	// Shutdown shuts down the client.
	Shutdown()
}

// SendMessageDescriptor describes a message to be sent.
type SendMessageDescriptor struct {

	// ServiceMixIdHash is the identity hash of the service mix that we send a message to.
	ServiceMixIdHash []byte

	// RecipientQueueID is the queue identity which will receive the message.
	RecipientQueueID []byte

	// SurbID can be set to nil in which case no SURB is generated.
	// On the other hand if SurbID is set then a SURB will be embedded
	// in the Sphinx packet payload so that the remote side may reply.
	SurbID *[constants.SURBIDLength]byte

	// Payload is the message payload.
	Payload []byte
}

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
		recipient []byte,
		entryMixIdHash *[32]byte,
		surbID *[constants.SURBIDLength]byte,
		payload []byte) (packet []byte, surbKey []byte, rtt time.Duration, err error)
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
	dstId []byte,
	dstMix *[32]byte,
	srcId []byte,
	srcMix *[32]byte,
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

// Session is the cryptographic noise protocol session with the entry mix and
// manages all that is related to sending and receiving messages.
type Session interface {

	// Start initiates the network connections and starts the worker thread.
	Start()

	// SendMessage returns the chosen Round Trip Time of the Sphinx packet which was sent.
	SendMessage(message *SendMessageDescriptor) (rtt time.Duration, err error)

	// SendSphinxPacket sends the given Sphinx packet.
	SendSphinxPacket(pkt []byte) error

	// CurrentDocument returns the current PKI doc.
	CurrentDocument() *pki.Document

	// Shutdown shuts down the session.
	Shutdown()
}

// AutomaticRepeatRequest is a type of error correction strategy where
// dropped packets are resent.
type AutomaticRepeatRequest interface {

	// Start initiates the network connections and starts the worker thread.
	Start()

	// SendMessage returns the chosen Round Trip Time of the Sphinx packet which was sent.
	SendMessage(message *SendMessageDescriptor, sequence uint64) (rtt time.Duration, err error)

	// Shutdown shuts down the session.
	Shutdown()
}
