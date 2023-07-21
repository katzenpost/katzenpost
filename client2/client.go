package client2

import (
	"os"
	"sync"
	"time"

	"github.com/charmbracelet/log"

	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

// Client manages startup, shutdow, creating new connections and reconnecting.
type Client struct {
	sync.RWMutex

	// messagePollInterval is the interval at which the server will be
	// polled for new messages if the queue is believed to be empty.
	// XXX This will go away once we get rid of polling.
	messagePollInterval time.Duration

	pki  *pki
	cfg  *config.Config
	log  *log.Logger
	conn *connection

	sphinx *sphinx.Sphinx
	geo    *geo.Geometry

	haltedCh chan interface{}
	haltOnce sync.Once
}

// Shutdown cleanly shuts down a given Client instance.
func (c *Client) Shutdown() {
	c.haltOnce.Do(func() { c.halt() })
}

// Wait waits till the Client is terminated for any reason.
func (c *Client) Wait() {
	<-c.haltedCh
}

func (c *Client) halt() {
	c.log.Info("Starting graceful shutdown.")

	if c.conn != nil {
		c.conn.Halt()
		// nil out after the PKI is torn down due to a dependency.
	}

	if c.pki != nil {
		c.pki.Halt()
		c.pki = nil
	}
	c.conn = nil

	c.log.Info("Shutdown complete.")
	close(c.haltedCh)
}

// XXX This will go away once we get rid of polling.
func (c *Client) SetPollInterval(interval time.Duration) {
	c.Lock()
	c.messagePollInterval = interval
	c.Unlock()
}

// XXX This will go away once we get rid of polling.
func (c *Client) GetPollInterval() time.Duration {
	c.RLock()
	defer c.RUnlock()
	return c.messagePollInterval
}

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

// New creates a new Client with the provided configuration.
func New(cfg *config.Config) (*Client, error) {
	if err := cfg.FixupAndValidate(); err != nil {
		return nil, err
	}

	c := new(Client)
	c.geo = cfg.SphinxGeometry
	var err error
	c.sphinx, err = sphinx.FromGeometry(cfg.SphinxGeometry)
	if err != nil {
		return nil, err
	}
	c.cfg = cfg
	c.log = log.NewWithOptions(os.Stderr, log.Options{
		ReportTimestamp: true,
		Prefix:          "client2",
	})

	c.haltedCh = make(chan interface{})

	c.log.Info("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")

	c.conn = newConnection(c)
	c.pki = newPKI(c)
	c.pki.start()
	c.conn.start()
	if c.cfg.CachedDocument != nil {
		// connectWorker waits for a pki fetch, we already have a document cached, so wake the worker
		c.conn.onPKIFetch()
	}

	return c, nil
}
