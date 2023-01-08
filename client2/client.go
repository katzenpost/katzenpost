package client2

import (
	"time"

	"github.com/katzenpost/katzenpost/core/pki"
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
