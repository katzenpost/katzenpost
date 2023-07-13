package client2

import (
	mRand "math/rand"
	"sync"

	"github.com/charmbracelet/log"

	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

// Client manages startup, shutdow, creating new connections and reconnecting.
type Client struct {
	//	pki  *pki
	cfg *config.Config
	log *log.Logger
	//	conn *connection

	geo *geo.Geometry

	rng *mRand.Rand

	displayName string

	haltedCh chan interface{}
	haltOnce sync.Once
}

/*
	// ReconnectOldSession reuses the old noise protocol key to reconnect to
	// a previously selected entry mix.
	ReconnectOldSession(Session) error

	// NewSession generates a new noise protocol key and connects to a randomly
	// selected entry mix.
	NewSession() (Session, error)
4
	// Wait waits for the client to shut down.
	Wait()

	// Shutdown shuts down the client.
	Shutdown()
*/

// SendMessageDescriptor describes a message to be sent.
type SendMessageDescriptor struct {

	// Priority is the per-application message priority
	Priority uint64

	// DestinationIdHash is 32 byte hash of the destination's
	// identity public key.
	DestinationIdHash []byte

	// RecipientQueueID is the queue identity which will receive the message.
	RecipientQueueID []byte

	// SurbID can be set to nil in which case no SURB is generated.
	// If SurbID is set then a SURB will be embedded
	// in the Sphinx packet payload so that the remote side may reply.
	SurbID *[constants.SURBIDLength]byte

	// Payload is the message payload.
	Payload []byte
}

// Session is the cryptographic noise protocol session with the entry mix and
// manages all that is related to sending and receiving messages.
type Session struct{}

/*
	// Start initiates the network connections and starts the worker thread.
	Start()

	// SendMessage returns the chosen Round Trip Time of the Sphinx packet which was sent.
	SendMessage(message *SendMessageDescriptor) (rtt time.Duration, err error)

	// SendSphinxPacket sends the given Sphinx packet.
	SendSphinxPacket(pkt []byte) error

	// CurrentDocument returns the current PKI doc.
	CurrentDocument() *cpki.Document

	// Shutdown shuts down the session.
	Shutdown()
*/
