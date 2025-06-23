// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package thin provides a lightweight client interface for the Katzenpost mixnet.
//
// The thin client package implements a simplified client that communicates with
// a full client daemon process via Unix domain sockets or TCP connections. This
// architecture separates the complex cryptographic operations and network management
// from the application layer, allowing applications to interact with the mixnet
// through a clean, high-level API.
//
// Key Features:
//   - Asynchronous message sending and receiving
//   - Pigeonhole channel support for persistent communication
//   - Automatic Repeat Request (ARQ) for reliable message delivery
//   - Event-driven architecture with customizable event handling
//   - Support for both TCP and Unix domain socket connections
//   - Built-in payload validation and size checking
//
// The thin client handles:
//   - Connection management with the client daemon
//   - Message serialization and deserialization
//   - Event routing and correlation
//   - Channel lifecycle management
//   - Error handling and reporting
//
// Example usage:
//
//	cfg := &Config{
//		Network: "unix",
//		Address: "/tmp/katzenpost.sock",
//		SphinxGeometry: sphinxGeo,
//		PigeonholeGeometry: pigeonholeGeo,
//	}
//
//	client := NewThinClient(cfg, logging)
//	err := client.Dial()
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer client.Close()
//
//	// Send a message
//	payload := []byte("Hello, mixnet!")
//	err = client.SendMessage(surbID, payload, destNode, destQueue)
//	if err != nil {
//		log.Fatal(err)
//	}
package thin

import (
	"context"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/fxamacker/cbor/v2"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client2/common"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/pigeonhole"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
)

const (
	// MessageIDLength defines the length in bytes of message identifiers used
	// throughout the thin client protocol for correlating requests and responses.
	MessageIDLength = 16
)

// GetRandomCourier is a wrapper around pigeonhole.GetRandomCourier for convenience.
// It returns a randomly selected courier node from the PKI document along with
// its identity hash, which can be used for routing pigeonhole messages.
//
// Parameters:
//   - doc: The PKI document containing available courier nodes
//
// Returns:
//   - *[hash.HashSize]byte: The identity hash of the selected courier
//   - []byte: The courier's identity key bytes
func GetRandomCourier(doc *cpki.Document) (*[hash.HashSize]byte, []byte) {
	return pigeonhole.GetRandomCourier(doc)
}

var (
	// Common error variables for consistent error handling across the thin client.
	// These errors are reused to avoid allocating new error objects repeatedly.

	// errContextCannotBeNil is returned when a required context parameter is nil.
	errContextCannotBeNil = errors.New("context cannot be nil")

	// errConnectionLost is returned when the connection to the daemon is lost.
	errConnectionLost = errors.New("connection lost")

	// errHalting is returned when operations are interrupted due to client shutdown.
	errHalting = errors.New("halting")
)

// ThinResponse encapsulates a message response that is passed to client applications.
// This type is used to correlate responses with their corresponding requests using
// either SURB IDs or message IDs, depending on the messaging pattern used.
//
// ThinResponse is typically used in scenarios where applications need to handle
// responses asynchronously or when implementing custom message correlation logic.
type ThinResponse struct {
	// SURBID is a unique identifier for this response that should precisely match
	// the application's chosen SURBID of the sent message. This field is used for
	// correlating responses when using Single Use Reply Blocks (SURBs).
	//
	// This field will be nil if the original message was sent without a SURB.
	SURBID *[sConstants.SURBIDLength]byte

	// ID is the unique identifier for the corresponding sent message. This field
	// is used for message correlation in ARQ (Automatic Repeat Request) scenarios
	// and other cases where message IDs are used for tracking.
	//
	// This field may be nil if the message was sent without an explicit ID.
	ID *[MessageIDLength]byte

	// Payload contains the decrypted response payload. This is the actual message
	// content received from the destination service or node.
	//
	// The payload format and content depend on the specific service or protocol
	// being used over the mixnet.
	Payload []byte
}

// ThinClient provides a lightweight interface for communicating with the Katzenpost mixnet
// through a client daemon process. It handles the protocol communication, event management,
// and message correlation while delegating all cryptographic operations to the daemon.
//
// The ThinClient is designed to be used by applications that need to send and receive
// messages through the mixnet without implementing the full complexity of the Katzenpost
// protocol stack. It provides both synchronous and asynchronous messaging patterns,
// supports pigeonhole channels for persistent communication, and includes built-in
// reliability features like ARQ (Automatic Repeat Request).
//
// Key responsibilities:
//   - Managing the connection to the client daemon
//   - Serializing and deserializing protocol messages
//   - Routing events to appropriate handlers
//   - Correlating requests with responses
//   - Validating message sizes and parameters
//   - Providing both blocking and non-blocking API methods
//
// The client operates in an event-driven manner, where responses and notifications
// are delivered through an event system that applications can subscribe to.
type ThinClient struct {
	worker.Worker

	// Configuration and connection state
	cfg   *Config // Client configuration
	isTCP bool    // Whether using TCP (vs Unix domain socket)

	// Logging infrastructure
	log        *logging.Logger // Client logger instance
	logBackend *log.Backend    // Logging backend for creating additional loggers

	// Network connection to the daemon
	conn net.Conn // Active connection to the client daemon

	// PKI document management
	pkidoc      *cpki.Document // Current PKI document from the daemon
	pkidocMutex sync.RWMutex   // Protects pkidoc access

	// Event system for asynchronous communication
	eventSink   chan Event      // Main event channel for internal use
	drainAdd    chan chan Event // Channel for adding event subscribers
	drainRemove chan chan Event // Channel for removing event subscribers

	// Message correlation maps for different messaging patterns
	// These maps correlate message IDs with response channels for blocking operations

	// sentWaitChanMap is used by BlockingSendReliableMessage to wait for send confirmations
	sentWaitChanMap sync.Map // MessageID -> chan error

	// replyWaitChanMap is used by BlockingSendReliableMessage to wait for message replies
	replyWaitChanMap sync.Map // MessageID -> chan *MessageReplyEvent

	// readChannelWaitChanMap is used by ReadChannel to wait for read operation results
	readChannelWaitChanMap sync.Map // MessageID -> chan *ReadChannelReply
}

// Config contains the configuration parameters for a ThinClient instance.
// It specifies how the client should connect to the daemon and what protocol
// parameters to use for validation and communication.
type Config struct {
	// SphinxGeometry defines the Sphinx packet format parameters used by the client daemon.
	// This must match the geometry used by the daemon for proper message size validation.
	// The geometry includes packet length, header size, and payload capacity information.
	SphinxGeometry *geo.Geometry

	// PigeonholeGeometry defines the pigeonhole protocol parameters used for channel-based
	// communication. This includes box payload sizes and query/reply message formats.
	// Used for validating pigeonhole channel payloads before sending to the daemon.
	PigeonholeGeometry *pigeonholeGeo.Geometry

	// Network specifies the network type for connecting to the client daemon.
	// Supported values include "tcp", "tcp4", "tcp6", and "unix".
	// Use "unix" for Unix domain sockets (recommended for local communication).
	Network string

	// Address specifies the network address of the client daemon.
	// For TCP connections, this should be in the format "host:port".
	// For Unix domain sockets, this should be the path to the socket file.
	Address string
}

// FromConfig creates a thin client Config from a full client daemon configuration.
// This is a convenience function for extracting the necessary parameters from
// a daemon configuration when the thin client needs to connect to that daemon.
//
// Parameters:
//   - cfg: The full client daemon configuration
//
// Returns:
//   - *Config: A thin client configuration with the appropriate network and geometry settings
//
// Panics:
//   - If cfg.SphinxGeometry is nil
//   - If cfg.PigeonholeGeometry is nil
func FromConfig(cfg *config.Config) *Config {
	if cfg.SphinxGeometry == nil {
		panic("SphinxGeometry cannot be nil")
	}
	if cfg.PigeonholeGeometry == nil {
		panic("PigeonholeGeometry cannot be nil")
	}

	return &Config{
		SphinxGeometry:     cfg.SphinxGeometry,
		PigeonholeGeometry: cfg.PigeonholeGeometry,
		Network:            cfg.ListenNetwork,
		Address:            cfg.ListenAddress,
	}
}

// LoadFile loads a thin client configuration from a TOML file.
// This function reads and parses a TOML configuration file containing
// the thin client settings.
//
// Parameters:
//   - filename: Path to the TOML configuration file
//
// Returns:
//   - *Config: The parsed configuration
//   - error: Any error encountered during file reading or parsing
//
// The TOML file should contain sections for SphinxGeometry, PigeonholeGeometry,
// Network, and Address settings. See the Config type documentation for details
// on the expected structure.
func LoadFile(filename string) (*Config, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	cfg := new(Config)
	err = toml.Unmarshal(b, cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

// NewThinClient creates a new ThinClient instance with the specified configuration
// and logging settings. The client is initialized but not connected; call Dial()
// to establish the connection to the daemon.
//
// Parameters:
//   - cfg: Configuration specifying connection parameters and protocol geometries
//   - logging: Logging configuration for the client
//
// Returns:
//   - *ThinClient: A new thin client instance ready for connection
//
// Panics:
//   - If cfg.SphinxGeometry is nil
//   - If cfg.PigeonholeGeometry is nil
//   - If the logging backend cannot be initialized
//
// The returned client will have its event system initialized and ready to handle
// daemon communication once Dial() is called.
func NewThinClient(cfg *Config, logging *config.Logging) *ThinClient {
	if cfg.SphinxGeometry == nil {
		panic("SphinxGeometry cannot be nil")
	}
	if cfg.PigeonholeGeometry == nil {
		panic("PigeonholeGeometry cannot be nil")
	}

	logBackend, err := log.New(logging.File, logging.Level, logging.Disable)
	if err != nil {
		panic(err)
	}
	return &ThinClient{
		isTCP:       strings.HasPrefix(strings.ToLower(cfg.Network), cfg.Address),
		cfg:         cfg,
		log:         logBackend.GetLogger("thinclient"),
		logBackend:  logBackend,
		eventSink:   make(chan Event, 2),
		drainAdd:    make(chan chan Event),
		drainRemove: make(chan chan Event),
	}
}

// Shutdown gracefully shuts down the thin client by halting all worker goroutines.
// This is an alias for Halt() provided for consistency with other client interfaces.
// Use Close() for a more complete shutdown that also closes the network connection.
func (t *ThinClient) Shutdown() {
	t.Halt()
}

// GetConfig returns the current configuration used by the thin client.
// This includes network settings, protocol geometries, and other parameters
// that were specified when the client was created.
//
// Returns:
//   - *Config: The client's configuration
func (t *ThinClient) GetConfig() *Config {
	return t.cfg
}

// GetLogger creates a new logger instance with the specified prefix.
// This allows different components or subsystems to have their own
// loggers while sharing the same logging backend configuration.
//
// Parameters:
//   - prefix: A string prefix to identify log messages from this logger
//
// Returns:
//   - *logging.Logger: A new logger instance with the specified prefix
func (t *ThinClient) GetLogger(prefix string) *logging.Logger {
	return t.logBackend.GetLogger(prefix)
}

// Close performs a graceful shutdown of the thin client, including:
//   - Sending a close notification to the daemon
//   - Closing the network connection
//   - Halting all worker goroutines
//   - Closing the event sink channel
//
// This method should be called when the application is finished using the client
// to ensure proper cleanup of resources. It's safe to call Close() multiple times.
//
// Returns:
//   - error: Any error encountered during the close process
//
// Note: After calling Close(), the client cannot be reused and a new instance
// must be created for further communication.
func (t *ThinClient) Close() error {

	req := &Request{
		ThinClose: &ThinClose{},
	}
	err := t.writeMessage(req)
	if err != nil {
		return err
	}

	err = t.conn.Close()
	t.Halt()
	close(t.eventSink)
	return err
}

// Dial dials the client daemon
func (t *ThinClient) Dial() error {
	t.log.Debug("Dial begin")

	network := t.cfg.Network
	address := t.cfg.Address

	switch network {
	case "tcp6":
		fallthrough
	case "tcp4":
		fallthrough
	case "tcp":
		fallthrough
	case "unix":
		var err error
		t.conn, err = net.Dial(network, address)
		if err != nil {
			return err
		}
	}

	// WAIT UNTIL we have a Noise cryptographic connection with an edge node
	t.log.Debugf("Waiting for a connection status message")
	message1, err := t.readMessage()
	if err != nil {
		return err
	}
	if message1.ConnectionStatusEvent == nil {
		panic("bug: thin client protocol sequence violation")
	}
	if !message1.ConnectionStatusEvent.IsConnected {
		return errors.New("not connected")
	}

	t.log.Debugf("Waiting for a PKI doc message")
	message2, err := t.readMessage()
	if err != nil {
		return err
	}
	if message2.NewPKIDocumentEvent == nil {
		panic("bug: thin client protocol sequence violation")
	}
	t.parsePKIDoc(message2.NewPKIDocumentEvent.Payload)
	t.Go(t.eventSinkWorker)
	t.Go(t.worker)
	t.log.Debug("Dial end")
	return nil
}

func (t *ThinClient) writeMessage(request *Request) error {
	// Check payload size for SendMessage and SendARQMessage
	var payload []byte
	if request.SendMessage != nil {
		payload = request.SendMessage.Payload
	} else if request.SendARQMessage != nil {
		payload = request.SendARQMessage.Payload
	}
	if payload != nil && len(payload) > t.cfg.SphinxGeometry.UserForwardPayloadLength {
		return fmt.Errorf("payload size %d exceeds maximum allowed size %d", len(payload), t.cfg.SphinxGeometry.UserForwardPayloadLength)
	}

	blob, err := cbor.Marshal(request)
	if err != nil {
		return err
	}

	const blobPrefixLen = 4

	prefix := make([]byte, blobPrefixLen)
	binary.BigEndian.PutUint32(prefix, uint32(len(blob)))
	toSend := append(prefix, blob...)
	count, err := t.conn.Write(toSend)
	if err != nil {
		return err
	}
	if count != len(toSend) {
		return fmt.Errorf("send error: failed to write length prefix: %d != %d", count, len(toSend))
	}
	return nil
}

func (t *ThinClient) readMessage() (*Response, error) {
	const messagePrefixLen = 4

	prefix := make([]byte, messagePrefixLen)
	_, err := io.ReadFull(t.conn, prefix)
	if err != nil {
		return nil, err
	}

	prefixLen := binary.BigEndian.Uint32(prefix)
	message := make([]byte, prefixLen)
	_, err = io.ReadFull(t.conn, message)
	if err != nil {
		return nil, err
	}

	response := &Response{}
	err = cbor.Unmarshal(message, response)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (t *ThinClient) worker() {
	for {
		select {
		case <-t.HaltCh():
			return
		default:
		}

		message, err := t.readMessage()
		if err != nil {
			t.log.Errorf("thin client ReceiveMessage failed: %v", err)
			if err == io.EOF {
				// XXX: should we halt ThinClient on EOF??
				go t.Halt()
				return
			}
			continue
		}
		if message == nil {
			go t.Halt()
			return
		}

		switch {
		case message.ShutdownEvent != nil:
			go t.Halt()
			return
		case message.MessageIDGarbageCollected != nil:
			t.log.Debug("MessageIDGarbageCollected")
			select {
			case t.eventSink <- message.MessageIDGarbageCollected:
				continue
			case <-t.HaltCh():
				return
			}
		case message.ConnectionStatusEvent != nil:
			t.log.Debug("ConnectionStatusEvent")
			select {
			case t.eventSink <- message.ConnectionStatusEvent:
				continue
			case <-t.HaltCh():
				return
			}
		case message.NewPKIDocumentEvent != nil:
			t.log.Debug("NewPKIDocumentEvent")
			doc, err := t.parsePKIDoc(message.NewPKIDocumentEvent.Payload)
			if err != nil {
				t.log.Fatalf("parsePKIDoc %s", err)
			}
			event := &NewDocumentEvent{
				Document: doc,
			}
			select {
			case t.eventSink <- event:
				continue
			case <-t.HaltCh():
				return
			}
		case message.MessageSentEvent != nil:
			t.log.Debug("MessageSentEvent")
			isArq := false
			if message.MessageSentEvent.MessageID != nil {
				sentWaitChanRaw, ok := t.sentWaitChanMap.Load(*message.MessageSentEvent.MessageID)
				if ok {
					isArq = true
					sentWaitChan := sentWaitChanRaw.(chan error)
					var err error
					if message.MessageSentEvent.ErrorCode != ThinClientSuccess {
						err = errors.New(ThinClientErrorToString(message.MessageSentEvent.ErrorCode))
					}
					select {
					case sentWaitChan <- err:
					case <-t.HaltCh():
						return
					}
				}
			}
			if !isArq {
				select {
				case t.eventSink <- message.MessageSentEvent:
					continue
				case <-t.HaltCh():
					return
				}
			}
		case message.MessageReplyEvent != nil:
			t.log.Debug("MessageReplyEvent")
			if message.MessageReplyEvent.Payload == nil {
				t.log.Error("message.Payload is nil")
			}
			isArq := false
			if message.MessageReplyEvent.MessageID != nil {
				replyWaitChanRaw, ok := t.replyWaitChanMap.Load(*message.MessageReplyEvent.MessageID)
				if ok {
					isArq = true
					replyWaitChan := replyWaitChanRaw.(chan *MessageReplyEvent)
					select {
					case replyWaitChan <- message.MessageReplyEvent:
					case <-t.HaltCh():
						return
					}
				}
			}
			if !isArq {
				select {
				case t.eventSink <- message.MessageReplyEvent:
				case <-t.HaltCh():
					return
				}
			}
		case message.CreateWriteChannelReply != nil:
			t.log.Debug("CreateWriteChannelReply")
			select {
			case t.eventSink <- message.CreateWriteChannelReply:
				continue
			case <-t.HaltCh():
				return
			}
		case message.CreateReadChannelReply != nil:
			t.log.Debug("CreateReadChannelReply")
			select {
			case t.eventSink <- message.CreateReadChannelReply:
				continue
			case <-t.HaltCh():
				return
			}
		case message.WriteChannelReply != nil:
			t.log.Debug("WriteChannelReply")
			select {
			case t.eventSink <- message.WriteChannelReply:
				continue
			case <-t.HaltCh():
				return
			}
		case message.ReadChannelReply != nil:
			t.log.Debugf("ReadChannelReply: MessageID %x, ChannelID %d, SendMessagePayload size %d bytes",
				message.ReadChannelReply.MessageID[:], message.ReadChannelReply.ChannelID, len(message.ReadChannelReply.SendMessagePayload))
			isDirectReply := false
			if message.ReadChannelReply.MessageID != nil {
				readWaitChanRaw, ok := t.readChannelWaitChanMap.Load(*message.ReadChannelReply.MessageID)
				if ok {
					isDirectReply = true
					readWaitChan := readWaitChanRaw.(chan *ReadChannelReply)
					select {
					case readWaitChan <- message.ReadChannelReply:
					case <-t.HaltCh():
						return
					}
				} else {
					t.log.Debugf("No wait channel found for MessageID %x", message.ReadChannelReply.MessageID[:])
				}
			}
			if !isDirectReply {
				select {
				case t.eventSink <- message.ReadChannelReply:
					continue
				case <-t.HaltCh():
					return
				}
			}
		default:
			t.log.Error("bug: received invalid thin client message")
		}
	}
}

// EventSink returns a channel that receives all Events. The channel should be closed when done.
func (t *ThinClient) EventSink() chan Event {
	// add a new event sink receiver
	ch := make(chan Event, 1)
	t.drainAdd <- ch
	return ch
}

// StopEventSink tells eventSinkWorker to stop sending events to ch
func (t *ThinClient) StopEventSink(ch chan Event) {
	t.drainRemove <- ch
}

// eventSinkWorker adds and removes channels receiving Events
func (t *ThinClient) eventSinkWorker() {
	t.log.Debug("STARTING eventSinkWorker")
	defer t.log.Debug("STOPPING eventSinkWorker")
	drains := make(map[chan Event]struct{}, 0)
	for {
		select {
		case <-t.HaltCh():
			// stop thread on shutdown
			return
		case drain := <-t.drainAdd:
			// Only add buffered channels to prevent blocking
			if cap(drain) == 0 {
				t.log.Warning("Attempting to add unbuffered channel to eventSink drains - ignoring")
				continue
			}
			drains[drain] = struct{}{}
		case drain := <-t.drainRemove:
			delete(drains, drain)
		case event := <-t.eventSink:
			bad := make([]chan Event, 0)
			for drain := range drains {
				select {
				case <-t.HaltCh():
					return
				case drain <- event:
					// Successfully sent event
				case <-time.After(100 * time.Millisecond):
					// Channel blocked for too long
					t.log.Warning("Removing unresponsive channel from eventSink drains")
					bad = append(bad, drain)
				}
			}
			// remove blocked drains
			for _, drain := range bad {
				delete(drains, drain)
			}
		}
	}
}

func (t *ThinClient) parsePKIDoc(payload []byte) (*cpki.Document, error) {
	doc := &cpki.Document{}
	err := cbor.Unmarshal(payload, doc)
	if err != nil {
		t.log.Errorf("failed to unmarshal CBOR PKI doc: %s", err.Error())
		return nil, err
	}
	t.pkidocMutex.Lock()
	t.pkidoc = doc
	t.pkidocMutex.Unlock()
	return doc, nil
}

// PKIDocument returns the thin client's current reference to the PKI doc
func (t *ThinClient) PKIDocument() *cpki.Document {
	t.pkidocMutex.RLock()
	defer t.pkidocMutex.RUnlock()
	return t.pkidoc
}

// GetServices returns the services matching the specified service name
func (t *ThinClient) GetServices(capability string) ([]*common.ServiceDescriptor, error) {
	doc := t.PKIDocument()
	descriptors := common.FindServices(capability, doc)
	if len(descriptors) == 0 {
		return nil, errors.New("error, GetService failure, service not found in pki doc")
	}
	return descriptors, nil
}

// GetService returns a randomly selected service
// matching the specified service name
func (t *ThinClient) GetService(serviceName string) (*common.ServiceDescriptor, error) {
	serviceDescriptors, err := t.GetServices(serviceName)
	if err != nil {
		return nil, err
	}
	return serviceDescriptors[rand.NewMath().Intn(len(serviceDescriptors))], nil
}

// NewMessageID returns a new message id.
func (t *ThinClient) NewMessageID() *[MessageIDLength]byte {
	id := new([MessageIDLength]byte)
	_, err := rand.Reader.Read(id[:])
	if err != nil {
		panic(err)
	}
	return id
}

// NewSURBID returns a new surb id.
func (t *ThinClient) NewSURBID() *[sConstants.SURBIDLength]byte {
	id := new([sConstants.SURBIDLength]byte)
	_, err := rand.Reader.Read(id[:])
	if err != nil {
		panic(err)
	}
	return id
}

// SendMessageWithoutReply sends a message encapsulated in a Sphinx packet, without any SURB.
// No reply will be possible.
func (t *ThinClient) SendMessageWithoutReply(payload []byte, destNode *[32]byte, destQueue []byte) error {
	req := &Request{
		SendMessage: &SendMessage{
			WithSURB:          false,
			Payload:           payload,
			DestinationIdHash: destNode,
			RecipientQueueID:  destQueue,
		},
	}

	return t.writeMessage(req)
}

// SendMessage takes a message payload, a destination node, destination queue ID and a SURB ID and sends a message
// along with a SURB so that you can later receive the reply along with the SURBID you choose.
// This method of sending messages should be considered to be asynchronous because it does NOT actually wait until
// the client daemon sends the message. Nor does it wait for a reply. The only blocking aspect to it's behavior is
// merely blocking until the client daemon receives our request to send a message.
func (t *ThinClient) SendMessage(surbID *[sConstants.SURBIDLength]byte, payload []byte, destNode *[32]byte, destQueue []byte) error {
	if surbID == nil {
		return errors.New("surbID cannot be nil")
	}
	req := &Request{
		SendMessage: &SendMessage{
			SURBID:            surbID,
			WithSURB:          true,
			Payload:           payload,
			DestinationIdHash: destNode,
			RecipientQueueID:  destQueue,
		},
	}

	return t.writeMessage(req)
}

// BlockingSendMessage blocks until a reply is received and returns it or an error.
func (t *ThinClient) BlockingSendMessage(ctx context.Context, payload []byte, destNode *[32]byte, destQueue []byte) ([]byte, error) {
	if ctx == nil {
		return nil, errContextCannotBeNil
	}
	surbID := t.NewSURBID()
	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)
	err := t.SendMessage(surbID, payload, destNode, destQueue)
	if err != nil {
		return nil, err
	}

	for {
		var event Event
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, errHalting
		}

		switch v := event.(type) {
		case *MessageIDGarbageCollected:
			t.log.Info("MessageIDGarbageCollected")
		case *ConnectionStatusEvent:
			t.log.Info("ConnectionStatusEvent")
			if !v.IsConnected {
				panic(errConnectionLost)
			}
		case *NewDocumentEvent:
			t.log.Info("NewPKIDocumentEvent")
		case *MessageSentEvent:
			t.log.Info("MessageSentEvent")
		case *MessageReplyEvent:
			t.log.Info("MessageReplyEvent")
			if hmac.Equal(surbID[:], v.SURBID[:]) {
				return v.Payload, nil
			} else {
				continue
			}
		default:
			panic("impossible event type")
		}
	}
	// unreachable
}

func (t *ThinClient) SendReliableMessage(messageID *[MessageIDLength]byte, payload []byte, destNode *[32]byte, destQueue []byte) error {
	req := &Request{
		SendARQMessage: &SendARQMessage{
			ID:                messageID,
			WithSURB:          true,
			Payload:           payload,
			DestinationIdHash: destNode,
			RecipientQueueID:  destQueue,
		},
	}

	return t.writeMessage(req)
}

// BlockingSendReliableMessage blocks until the message is reliably sent and the ARQ reply is received.
func (t *ThinClient) BlockingSendReliableMessage(ctx context.Context, messageID *[MessageIDLength]byte, payload []byte, destNode *[32]byte, destQueue []byte) (reply []byte, err error) {
	if ctx == nil {
		return nil, errContextCannotBeNil
	}

	if messageID == nil {
		messageID = new([MessageIDLength]byte)
		_, err := io.ReadFull(rand.Reader, messageID[:])
		if err != nil {
			return nil, err
		}
	}

	req := &Request{
		SendARQMessage: &SendARQMessage{
			ID:                messageID,
			WithSURB:          true,
			Payload:           payload,
			DestinationIdHash: destNode,
			RecipientQueueID:  destQueue,
		},
	}

	sentWaitChan := make(chan error)
	t.sentWaitChanMap.Store(*messageID, sentWaitChan)
	defer t.sentWaitChanMap.Delete(*messageID)

	replyWaitChan := make(chan *MessageReplyEvent)
	t.replyWaitChanMap.Store(*messageID, replyWaitChan)
	defer t.replyWaitChanMap.Delete(*messageID)

	err = t.writeMessage(req)
	if err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err = <-sentWaitChan:
		if err != nil {
			return nil, err
		}
	case <-t.HaltCh():
		return nil, errHalting
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case reply := <-replyWaitChan:
		if reply.ErrorCode != ThinClientSuccess {
			return nil, errors.New(ThinClientErrorToString(reply.ErrorCode))
		}
		return reply.Payload, nil
	case <-t.HaltCh():
		return nil, errHalting
	}

	// unreachable
}

// CreateWriteChannel creates a new pigeonhole write channel and returns the channel ID, read capability, and write capability.
func (t *ThinClient) CreateWriteChannel(ctx context.Context, WriteCap *bacap.WriteCap, messageBoxIndex *bacap.MessageBoxIndex) (uint16, *bacap.ReadCap, *bacap.WriteCap, *bacap.MessageBoxIndex, error) {
	if ctx == nil {
		return 0, nil, nil, nil, errContextCannotBeNil
	}

	switch {
	case WriteCap == nil && messageBoxIndex == nil:
		// Creating a new channel
	case WriteCap != nil && messageBoxIndex == nil:
		return 0, nil, nil, nil, errors.New("messageBoxIndex cannot be nil when resuming an existing channel")
	case WriteCap == nil && messageBoxIndex != nil:
		return 0, nil, nil, nil, errors.New("WriteCap cannot be nil when resuming an existing channel")
	case WriteCap != nil && messageBoxIndex != nil:
		// Resuming an existing channel
	}

	req := &Request{
		CreateWriteChannel: &CreateWriteChannel{
			WriteCap:        WriteCap,
			MessageBoxIndex: messageBoxIndex,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return 0, nil, nil, nil, err
	}

	for {
		var event Event
		select {
		case <-ctx.Done():
			return 0, nil, nil, nil, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return 0, nil, nil, nil, errHalting
		}

		switch v := event.(type) {
		case *CreateWriteChannelReply:
			if v.ErrorCode != ThinClientSuccess {
				return 0, nil, nil, nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.ChannelID, v.ReadCap, v.WriteCap, v.NextMessageIndex, nil
		case *ConnectionStatusEvent:
			if !v.IsConnected {
				return 0, nil, nil, nil, errConnectionLost
			}
		default:
			// Ignore other events
		}
	}
}

// CreateReadChannel creates a read channel from a read capability.
func (t *ThinClient) CreateReadChannel(ctx context.Context, readCap *bacap.ReadCap, messageBoxIndex *bacap.MessageBoxIndex) (uint16, *bacap.MessageBoxIndex, error) {
	if ctx == nil {
		return 0, nil, errContextCannotBeNil
	}
	if readCap == nil {
		return 0, nil, errors.New("readCap cannot be nil")
	}

	req := &Request{
		CreateReadChannel: &CreateReadChannel{
			ReadCap:         readCap,
			MessageBoxIndex: messageBoxIndex,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return 0, nil, err
	}

	for {
		var event Event
		select {
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return 0, nil, errHalting
		}

		switch v := event.(type) {
		case *CreateReadChannelReply:
			if v.ErrorCode != ThinClientSuccess {
				return 0, nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.ChannelID, v.NextMessageIndex, nil
		case *ConnectionStatusEvent:
			if !v.IsConnected {
				return 0, nil, errConnectionLost
			}
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// WriteChannel prepares a write message for a pigeonhole channel and returns the SendMessage payload and next MessageBoxIndex.
// The thin client must then call SendMessage with the returned payload to actually send the message.
func (t *ThinClient) WriteChannel(ctx context.Context, channelID uint16, payload []byte) ([]byte, *bacap.MessageBoxIndex, error) {
	if ctx == nil {
		return nil, nil, errContextCannotBeNil
	}

	// Validate payload size against pigeonhole geometry
	if len(payload) > t.cfg.PigeonholeGeometry.BoxPayloadLength {
		return nil, nil, fmt.Errorf("payload size %d exceeds maximum allowed size %d", len(payload), t.cfg.PigeonholeGeometry.BoxPayloadLength)
	}

	req := &Request{
		WriteChannel: &WriteChannel{
			ChannelID: channelID,
			Payload:   payload,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return nil, nil, err
	}

	for {
		var event Event
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, nil, errHalting
		}

		switch v := event.(type) {
		case *WriteChannelReply:
			if v.ErrorCode != ThinClientSuccess {
				return nil, nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.SendMessagePayload, v.NextMessageIndex, nil
		case *ConnectionStatusEvent:
			if !v.IsConnected {
				return nil, nil, errConnectionLost
			}
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// ReadChannel prepares a read query for a pigeonhole channel and returns the payload and next MessageBoxIndex.
// The thin client must then call SendMessage (or similar methods) with the returned payload to actually send the query.
func (t *ThinClient) ReadChannel(ctx context.Context, channelID uint16, messageID *[MessageIDLength]byte) ([]byte, *bacap.MessageBoxIndex, error) {
	if ctx == nil {
		return nil, nil, errContextCannotBeNil
	}
	if messageID == nil {
		return nil, nil, errors.New("messageID cannot be nil")
	}

	req := &Request{
		ReadChannel: &ReadChannel{
			ChannelID: channelID,
			MessageID: messageID,
		},
	}

	// Set up direct message ID correlation for ReadChannelReply
	// Always create or reuse a persistent wait channel for this MessageID
	readWaitChanRaw, exists := t.readChannelWaitChanMap.Load(*messageID)
	var readWaitChan chan *ReadChannelReply
	if exists {
		readWaitChan = readWaitChanRaw.(chan *ReadChannelReply)
	} else {
		readWaitChan = make(chan *ReadChannelReply, 1) // Buffered to prevent blocking
		t.readChannelWaitChanMap.Store(*messageID, readWaitChan)
	}

	err := t.writeMessage(req)
	if err != nil {
		return nil, nil, err
	}

	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case reply := <-readWaitChan:
		if reply.ErrorCode != ThinClientSuccess {
			return nil, nil, errors.New(ThinClientErrorToString(reply.ErrorCode))
		}
		return reply.SendMessagePayload, reply.NextMessageIndex, nil
	case <-t.HaltCh():
		t.readChannelWaitChanMap.Delete(*messageID)
		return nil, nil, errHalting
	}
}

func (t *ThinClient) SendChannelQuery(
	ctx context.Context,
	channelID uint16,
	payload []byte,
	destNode *[32]byte,
	destQueue []byte,
) error {

	if ctx == nil {
		return errContextCannotBeNil
	}

	surbID := t.NewSURBID()
	req := &Request{
		SendMessage: &SendMessage{
			ChannelID:         &channelID,
			SURBID:            surbID,
			WithSURB:          true,
			Payload:           payload,
			DestinationIdHash: destNode,
			RecipientQueueID:  destQueue,
		},
	}

	return t.writeMessage(req)
}
