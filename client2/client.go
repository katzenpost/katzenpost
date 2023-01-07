package client2

import (
	"time"

	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
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

	// ServiceMixName is the name of the service mix that we send a message to.
	ServiceMixName string

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
		recipient []byte,
		provider string,
		surbID *[constants.SURBIDLength]byte,
		baseTime time.Time,
		isForward bool) (path []*sphinx.PathHop, rtt time.Time, err error)
}

// PacketFactory is used to compose Sphinx packets.
type PacketFactory interface {

	// ComposePacket is used to compose Sphinx packets. Returns
	// a Sphinx packet, a surbKey and round trip time or an error.
	ComposePacket(
		recipient []byte,
		provider string,
		surbID *[constants.SURBIDLength]byte,
		payload []byte) (packet []byte, surbKey []byte, rtt time.Duration, err error)
}

type packetFactory struct {
	pathFactory PathFactory
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
	}
	for _, opt := range opts {
		opt(factory)
	}
	return factory
}

type defaultPathFactory struct{} // TODO(david): easy peasy

// ComposePath is used to compose a Sphinx packet path. Returns
// path and round trip time or an error.
func (d *defaultPathFactory) ComposePath(
	recipient []byte,
	provider string,
	surbID *[constants.SURBIDLength]byte,
	baseTime time.Time,
	isForward bool) (path []*sphinx.PathHop, rtt time.Time, err error) {

	return nil, time.Now(), nil // XXX FIXME
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
