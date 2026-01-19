// SPDX-FileCopyrightText: © 2023, 2024, 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package thin provides a lightweight client API for the Katzenpost mixnet.
//
// # Overview
//
// The thin client package implements a client-daemon architecture where the thin client
// communicates with a separate client daemon process that handles the heavy cryptographic
// operations and mixnet protocol details. This design allows applications to integrate
// with Katzenpost without implementing the full complexity of the mixnet protocols.
//
// # Architecture
//
// The thin client connects to a client daemon via TCP or Unix domain sockets. The daemon
// handles:
//   - Sphinx packet creation and processing
//   - PKI document management and validation
//   - Mixnet routing and timing
//   - Cryptographic operations (encryption, decryption, signatures)
//   - Connection management to the mixnet
//
// The thin client provides a simple API for:
//   - Sending and receiving messages
//   - Creating and managing communication channels
//   - Handling events and status updates
//
// # APIs
//
// This package provides two main APIs:
//
// ## Legacy API (deprecated for new projects)
//
// The legacy API provides basic message sending functionality:
//   - SendMessage: Send a message with optional reply capability
//   - SendMessageWithoutReply: Send a fire-and-forget message
//   - BlockingSendMessage: Send a message and wait for reply
//   - SendReliableMessage: Send with automatic retransmission (ARQ)
//   - BlockingSendReliableMessage: Reliable send with blocking reply
//
// ## Pigeonhole Channel API (recommended)
//
// The new Pigeonhole protocol provides reliable, ordered communication channels:
//   - CreateWriteChannel: Create a new channel for sending messages
//   - CreateReadChannel: Create a channel for receiving messages
//   - WriteChannel: Prepare a message for transmission
//   - ReadChannel: Prepare a query to read the next message
//   - SendChannelQuery: Send prepared queries to the mixnet
//   - ResumeWriteChannel/ResumeReadChannel: Resume channels after restart
//
// # Basic Usage Example
//
//	// Load configuration
//	cfg, err := thin.LoadFile("thinclient.toml")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Create and connect thin client
//	logging := &config.Logging{Level: "INFO"}
//	client := thin.NewThinClient(cfg, logging)
//	err = client.Dial()
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer client.Close()
//
//	// Create a communication channel (Alice side)
//	ctx := context.Background()
//	channelID, readCap, writeCap, err := client.CreateWriteChannel(ctx)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Write a message
//	message := []byte("Hello, Bob!")
//	writeReply, err := client.WriteChannel(ctx, channelID, message)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Send the prepared message through the mixnet
//	destNode, destQueue, err := client.GetCourierDestination()
//	if err != nil {
//		log.Fatal(err)
//	}
//	messageID := client.NewMessageID()
//	_, err = client.SendChannelQueryAwaitReply(ctx, channelID,
//		writeReply.SendMessagePayload, destNode, destQueue, messageID)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// # Channel Communication Pattern
//
// Pigeonhole channels use a two-step process:
//
// 1. Prepare: Call WriteChannel or ReadChannel to prepare the cryptographic payload
// 2. Send: Call SendChannelQuery to actually transmit through the mixnet
//
// This separation allows for:
//   - State management and persistence
//   - Retry logic and error recovery
//   - Offline operation (preparation can happen without mixnet connectivity)
//
// # Error Handling
//
// The API uses structured error codes defined in thin_messages.go. Check the ErrorCode
// field in reply events and use ThinClientErrorToString() for human-readable messages.
//
// # Event Handling
//
// The thin client provides an event-driven interface:
//
//	eventSink := client.EventSink()
//	defer client.StopEventSink(eventSink)
//
//	for event := range eventSink {
//		switch e := event.(type) {
//		case *MessageReplyEvent:
//			// Handle message reply
//		case *ConnectionStatusEvent:
//			// Handle connection changes
//		case *NewDocumentEvent:
//			// Handle PKI updates
//		}
//	}
//
// # Configuration
//
// The thin client requires configuration specifying:
//   - Network and address of the client daemon
//   - Sphinx geometry parameters
//   - Pigeonhole geometry parameters
//
// See the testdata/thinclient.toml file for an example configuration.
//
// # Thread Safety
//
// The ThinClient is safe for concurrent use. Multiple goroutines can call methods
// simultaneously. However, individual channels and their state should be managed
// carefully in concurrent environments.
package thin

import (
	"bytes"
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
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/worker"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
)

const (
	// MessageIDLength is the length of a message ID in bytes.
	MessageIDLength = 16

	// QueryIDLength is the length of a query ID in bytes.
	QueryIDLength = 16
)

var (
	// Error variables for reuse
	errContextCannotBeNil = errors.New("context cannot be nil")
	errConnectionLost     = errors.New("connection lost")
	errHalting            = errors.New("halting")
)

// ThinResponse encapsulates a message response from the mixnet that is passed
// to the client application. This is part of the legacy API.
//
// ThinResponse contains the decrypted reply payload along with identifiers
// that allow the application to correlate responses with the original requests.
type ThinResponse struct {
	// SURBID is a unique identifier for this response that should precisely
	// match the application's chosen SURBID of the sent message. This allows
	// the application to correlate responses with requests when using the
	// legacy SendMessage API.
	SURBID *[sConstants.SURBIDLength]byte

	// ID is the unique identifier for the corresponding sent message.
	// This is used for message correlation in the legacy API.
	ID *[MessageIDLength]byte

	// Payload contains the decrypted response data from the destination service.
	// The format and content depend on the service being contacted.
	Payload []byte
}

// ThinClient handles communication between mixnet applications and the client daemon.
//
// The ThinClient implements a lightweight client architecture where cryptographic
// operations, PKI management, and mixnet protocol handling are delegated to a
// separate client daemon process. This design allows applications to integrate
// with Katzenpost without implementing the full complexity of the mixnet protocols.
//
// Key responsibilities of ThinClient:
//   - Maintain connection to the client daemon via TCP or Unix sockets
//   - Provide high-level APIs for message sending and channel operations
//   - Handle event distribution to application code
//   - Manage PKI document caching and epoch transitions
//   - Coordinate request/response correlation for blocking operations
//
// The ThinClient is safe for concurrent use by multiple goroutines.
//
// Lifecycle:
//  1. Create with NewThinClient()
//  2. Connect with Dial()
//  3. Use messaging/channel APIs
//  4. Clean up with Close()
//
// Example:
//
//	cfg, _ := thin.LoadFile("config.toml")
//	logging := &config.Logging{Level: "INFO"}
//	client := thin.NewThinClient(cfg, logging)
//	defer client.Close()
//
//	err := client.Dial()
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Use client for messaging...
type ThinClient struct {
	worker.Worker

	cfg   *Config
	isTCP bool

	log        *logging.Logger
	logBackend *log.Backend

	conn net.Conn

	pkidoc      *cpki.Document
	pkidocMutex sync.RWMutex

	// PKI document cache by epoch to ensure consistency during epoch transitions
	pkiDocCache     map[uint64]*cpki.Document
	pkiDocCacheLock sync.RWMutex

	eventSink   chan Event
	drainAdd    chan chan Event
	drainRemove chan chan Event

	isConnected bool

	// used by BlockingSendReliableMessage only
	sentWaitChanMap  sync.Map // MessageID -> chan error
	replyWaitChanMap sync.Map // MessageID -> chan *MessageReplyEvent
}

// Config contains the configuration parameters for a ThinClient.
//
// The configuration specifies how to connect to the client daemon and includes
// the cryptographic parameters that must match the daemon's configuration.
//
// Configuration can be loaded from a TOML file using LoadFile() or created
// programmatically. The SphinxGeometry and PigeonholeGeometry parameters
// must exactly match those used by the client daemon.
//
// Example TOML configuration:
//
//	Network = "tcp"
//	Address = "localhost:64331"
//
//	[SphinxGeometry]
//	  PacketLength = 3082
//	  NrHops = 5
//	  UserForwardPayloadLength = 2000
//	  # ... other Sphinx parameters
//
//	[PigeonholeGeometry]
//	  MaxPlaintextPayloadLength = 1553
//	  # ... other Pigeonhole parameters
type Config struct {
	// SphinxGeometry defines the Sphinx packet format parameters used by the
	// client daemon. This must exactly match the daemon's configuration to
	// ensure proper packet size validation and processing.
	SphinxGeometry *geo.Geometry

	// PigeonholeGeometry defines the Pigeonhole protocol parameters used for
	// channel operations. This must match the daemon's configuration for
	// proper payload size validation and channel operation compatibility.
	PigeonholeGeometry *pigeonholeGeo.Geometry

	// Network specifies the network type for connecting to the client daemon.
	// Supported values: "tcp", "tcp4", "tcp6", "unix"
	Network string

	// Address specifies the address to connect to the client daemon.
	// For TCP: "host:port" (e.g., "localhost:64331")
	// For Unix: path to socket file (e.g., "/tmp/katzenpost.sock")
	Address string
}

// FromConfig creates a thin client Config from a client daemon config.Config.
//
// This function extracts the relevant parameters from a full client daemon
// configuration and creates a thin client configuration that can connect to
// that daemon. The SphinxGeometry and PigeonholeGeometry are copied directly
// to ensure compatibility.
//
// Parameters:
//   - cfg: The client daemon configuration
//
// Returns:
//   - *Config: A thin client configuration compatible with the daemon
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
//
// The TOML file should contain the network connection parameters and
// cryptographic geometry specifications. See the package documentation
// for an example configuration format.
//
// Parameters:
//   - filename: Path to the TOML configuration file
//
// Returns:
//   - *Config: The loaded configuration
//   - error: Any error encountered reading or parsing the file
//
// Example:
//
//	cfg, err := thin.LoadFile("thinclient.toml")
//	if err != nil {
//		log.Fatal("Failed to load config:", err)
//	}
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

// NewThinClient creates a new ThinClient instance.
//
// This function initializes a new thin client with the provided configuration
// and logging settings. The client is created in a disconnected state; call
// Dial() to establish connection to the client daemon.
//
// The client will validate that required geometry parameters are present and
// set up internal channels and workers for event handling.
//
// Parameters:
//   - cfg: Configuration specifying daemon connection and crypto parameters
//   - logging: Logging configuration for the client
//
// Returns:
//   - *ThinClient: A new thin client instance ready for connection
//
// Panics:
//   - If cfg.SphinxGeometry is nil
//   - If cfg.PigeonholeGeometry is nil
//   - If logging configuration is invalid
//
// Example:
//
//	cfg, _ := thin.LoadFile("config.toml")
//	logging := &config.Logging{
//		Level: "INFO",
//		File:  "", // stdout
//	}
//	client := thin.NewThinClient(cfg, logging)
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
		pkiDocCache: make(map[uint64]*cpki.Document),
	}
}

// Shutdown cleanly shuts down the ThinClient instance.
//
// This method stops all background workers and closes the connection to the
// client daemon. It is equivalent to calling Halt() and is provided for
// compatibility. For proper cleanup, prefer using Close().
func (t *ThinClient) Shutdown() {
	t.Halt()
}

// GetConfig returns the client's configuration.
//
// Returns:
//   - *Config: The configuration used to create this client
func (t *ThinClient) GetConfig() *Config {
	return t.cfg
}

// GetLogger returns a logger instance with the specified prefix.
//
// This allows applications to create loggers that integrate with the thin
// client's logging system and maintain consistent log formatting.
//
// Parameters:
//   - prefix: String prefix for log messages from this logger
//
// Returns:
//   - *logging.Logger: A logger instance with the specified prefix
func (t *ThinClient) GetLogger(prefix string) *logging.Logger {
	return t.logBackend.GetLogger(prefix)
}

// IsConnected returns true if the client daemon is connected to the mixnet.
//
// This indicates whether the daemon has an active connection to the mixnet
// infrastructure. When false, the client is in "offline mode" where channel
// operations (prepare operations) will work but actual message transmission
// will fail.
//
// Returns:
//   - bool: true if daemon is connected to mixnet, false otherwise
func (t *ThinClient) IsConnected() bool {
	return t.isConnected
}

// Close gracefully shuts down the thin client and closes the daemon connection.
//
// This method performs a clean shutdown by:
//  1. Sending a close notification to the daemon
//  2. Closing the network connection
//  3. Stopping all background workers
//  4. Closing internal event channels
//
// After calling Close(), the ThinClient instance should not be used further.
// Any ongoing operations will be interrupted and may return errors.
//
// Returns:
//   - error: Any error encountered during shutdown
//
// Example:
//
//	defer client.Close() // Ensure cleanup
//
//	// Use client...
//
//	err := client.Close()
//	if err != nil {
//		log.Printf("Error during shutdown: %v", err)
//	}
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

// Dial establishes a connection to the client daemon and initializes the client.
//
// This method performs the complete connection handshake with the client daemon:
//  1. Establishes network connection (TCP or Unix socket)
//  2. Receives initial connection status from daemon
//  3. Receives initial PKI document
//  4. Starts background workers for event handling
//
// The client supports both online and offline modes. In offline mode (when the
// daemon is not connected to the mixnet), channel preparation operations will
// work but actual message transmission will fail.
//
// After successful connection, the client will automatically handle:
//   - PKI document updates
//   - Connection status changes
//   - Event distribution to application code
//
// Returns:
//   - error: Any error encountered during connection or handshake
//
// Example:
//
//	client := thin.NewThinClient(cfg, logging)
//	err := client.Dial()
//	if err != nil {
//		log.Fatal("Failed to connect to daemon:", err)
//	}
//	defer client.Close()
//
//	if !client.IsConnected() {
//		log.Println("Daemon is offline - limited functionality available")
//	}
func (t *ThinClient) Dial() error {

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

	// WAIT for connection status message from daemon
	t.log.Debugf("Waiting for a connection status message")
	message1, err := t.readMessage()
	if err != nil {
		return err
	}
	if message1.ConnectionStatusEvent == nil {
		panic("bug: thin client protocol sequence violation")
	}

	// Set connection state - allow both connected and offline modes
	t.isConnected = message1.ConnectionStatusEvent.IsConnected

	if !t.isConnected {
		t.log.Infof("Daemon is not connected to mixnet - entering offline mode (channel operations will work)")
	} else {
		t.log.Debugf("Daemon is connected to mixnet - full functionality available")
	}

	t.log.Debugf("Waiting for a PKI doc message")
	message2, err := t.readMessage()
	if err != nil {
		return err
	}
	if message2.NewPKIDocumentEvent == nil {
		panic("bug: thin client protocol sequence violation")
	}
	// Handle empty payload - daemon may not have a PKI document yet
	if len(message2.NewPKIDocumentEvent.Payload) > 0 {
		t.parsePKIDoc(message2.NewPKIDocumentEvent.Payload)
	} else {
		t.log.Infof("No PKI document available yet - will receive when available")
	}
	t.Go(t.eventSinkWorker)
	t.Go(t.worker)
	return nil
}

// writeMessage sends a request message to the client daemon over the connection.
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

// readMessage reads a response message from the client daemon over the connection.
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

// worker is the main background worker that processes incoming messages from the daemon.
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
			select {
			case t.eventSink <- message.MessageIDGarbageCollected:
				continue
			case <-t.HaltCh():
				return
			}
		case message.ConnectionStatusEvent != nil:
			select {
			case t.eventSink <- message.ConnectionStatusEvent:
				continue
			case <-t.HaltCh():
				return
			}
		case message.NewPKIDocumentEvent != nil:
			doc, err := t.parsePKIDoc(message.NewPKIDocumentEvent.Payload)
			if err != nil {
				t.log.Errorf("Failed to parse PKI document: %s", err)
				// Gracefully halt the client on PKI parsing failure
				go t.Halt()
				return
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
			isArq := false
			if message.MessageSentEvent.MessageID != nil {
				sentWaitChanRaw, ok := t.sentWaitChanMap.Load(*message.MessageSentEvent.MessageID)
				if ok {
					isArq = true
					sentWaitChan := sentWaitChanRaw.(chan error)
					var err error
					if message.MessageSentEvent.Err != "" {
						err = errors.New(message.MessageSentEvent.Err)
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
			if message.MessageReplyEvent.Payload == nil {
				if message.MessageReplyEvent.ErrorCode != ThinClientSuccess {
					t.log.Errorf("message.Payload is nil due to error: %s", ThinClientErrorToString(message.MessageReplyEvent.ErrorCode))
				} else {
					t.log.Error("message.Payload is nil")
				}
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

			/**  New Channel API **/

		case message.ChannelQuerySentEvent != nil:
			select {
			case t.eventSink <- message.ChannelQuerySentEvent:
				continue
			case <-t.HaltCh():
				return
			}
		case message.ChannelQueryReplyEvent != nil:
			select {
			case t.eventSink <- message.ChannelQueryReplyEvent:
				continue
			case <-t.HaltCh():
				return
			}
		case message.CreateReadChannelReply != nil:
			select {
			case t.eventSink <- message.CreateReadChannelReply:
				continue
			case <-t.HaltCh():
				return
			}
		case message.CreateWriteChannelReply != nil:
			select {
			case t.eventSink <- message.CreateWriteChannelReply:
				continue
			case <-t.HaltCh():
				return
			}

		case message.WriteChannelReply != nil:
			select {
			case t.eventSink <- message.WriteChannelReply:
				continue
			case <-t.HaltCh():
				return
			}
		case message.ReadChannelReply != nil:
			select {
			case t.eventSink <- message.ReadChannelReply:
				continue
			case <-t.HaltCh():
				return
			}
		case message.ResumeWriteChannelReply != nil:
			select {
			case t.eventSink <- message.ResumeWriteChannelReply:
				continue
			case <-t.HaltCh():
				return
			}
		case message.ResumeReadChannelReply != nil:
			select {
			case t.eventSink <- message.ResumeReadChannelReply:
				continue
			case <-t.HaltCh():
				return
			}
		case message.ResumeWriteChannelQueryReply != nil:
			select {
			case t.eventSink <- message.ResumeWriteChannelQueryReply:
				continue
			case <-t.HaltCh():
				return
			}
		case message.ResumeReadChannelQueryReply != nil:
			select {
			case t.eventSink <- message.ResumeReadChannelQueryReply:
				continue
			case <-t.HaltCh():
				return
			}

		default:
			t.log.Errorf("bug: received invalid thin client message: %v", message)
		}
	}
}

// EventSink returns a buffered channel that receives all events from the thin client.
//
// This method creates a new event channel that will receive copies of all events
// generated by the thin client, including:
//   - Connection status changes
//   - PKI document updates
//   - Message sent confirmations
//   - Message replies
//   - Channel operation results
//   - Error notifications
//
// The returned channel is buffered with capacity 1 to prevent blocking the
// event distribution system. Applications should process events promptly to
// avoid missing events.
//
// Important: Always call StopEventSink() when done with the channel to prevent
// resource leaks and ensure proper cleanup.
//
// Returns:
//   - chan Event: A buffered channel that will receive all client events
//
// Example:
//
//	eventSink := client.EventSink()
//	defer client.StopEventSink(eventSink)
//
//	for event := range eventSink {
//		switch e := event.(type) {
//		case *MessageReplyEvent:
//			fmt.Printf("Received reply: %s\n", e.Payload)
//		case *ConnectionStatusEvent:
//			fmt.Printf("Connection status: %v\n", e.IsConnected)
//		case *NewDocumentEvent:
//			fmt.Printf("New PKI document for epoch %d\n", e.Document.Epoch)
//		}
//	}
func (t *ThinClient) EventSink() chan Event {
	// add a new event sink receiver
	ch := make(chan Event, 1)
	t.drainAdd <- ch
	return ch
}

// StopEventSink stops sending events to the specified channel and cleans up resources.
//
// This method removes the channel from the event distribution system and should
// be called when the application is done processing events from a channel
// returned by EventSink(). Failure to call this method may result in resource
// leaks and continued event processing overhead.
//
// Parameters:
//   - ch: The event channel returned by EventSink() to stop
//
// Example:
//
//	eventSink := client.EventSink()
//	defer client.StopEventSink(eventSink) // Ensure cleanup
//
//	// Process events...
func (t *ThinClient) StopEventSink(ch chan Event) {
	t.drainRemove <- ch
}

// eventSinkWorker adds and removes channels receiving Events
func (t *ThinClient) eventSinkWorker() {
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

	// Update current document
	t.pkidocMutex.Lock()
	t.pkidoc = doc
	t.pkidocMutex.Unlock()

	// Cache document by epoch for consistency during epoch transitions
	t.pkiDocCacheLock.Lock()
	t.pkiDocCache[doc.Epoch] = doc
	t.log.Debugf("Cached PKI document for epoch %d", doc.Epoch)

	// Clean up old cached documents (keep last 5 epochs)
	const maxCachedEpochs = 5
	if len(t.pkiDocCache) > maxCachedEpochs {
		oldestEpoch := doc.Epoch - maxCachedEpochs
		for epoch := range t.pkiDocCache {
			if epoch < oldestEpoch {
				delete(t.pkiDocCache, epoch)
			}
		}
	}
	t.pkiDocCacheLock.Unlock()

	return doc, nil
}

// PKIDocument returns the thin client's current PKI document.
//
// The PKI document contains the current network topology, service information,
// and cryptographic parameters for the current epoch. This document is
// automatically updated when the client daemon receives new PKI information.
//
// Returns:
//   - *cpki.Document: The current PKI document, or nil if none available
//
// Thread-safe: This method can be called concurrently from multiple goroutines.
func (t *ThinClient) PKIDocument() *cpki.Document {
	t.pkidocMutex.RLock()
	defer t.pkidocMutex.RUnlock()
	return t.pkidoc
}

// PKIDocumentForEpoch returns the PKI document for a specific epoch from cache.
//
// This method provides access to PKI documents from previous epochs that are
// cached by the client. This is important for maintaining consistency during
// epoch transitions where different participants might be using PKI documents
// from different epochs, which can lead to different envelope hashes and
// communication failures.
//
// The client automatically caches the last 5 epochs of PKI documents. If the
// requested epoch is not in cache, the current document is returned as a
// fallback.
//
// Parameters:
//   - epoch: The epoch number for which to retrieve the PKI document
//
// Returns:
//   - *cpki.Document: The PKI document for the specified epoch
//   - error: Error if no document is available for the epoch
//
// Example:
//
//	// Get document for a specific epoch during channel operations
//	doc, err := client.PKIDocumentForEpoch(12345)
//	if err != nil {
//		log.Printf("No PKI document for epoch %d: %v", 12345, err)
//		return
//	}
//	// Use doc for epoch-specific operations...
func (t *ThinClient) PKIDocumentForEpoch(epoch uint64) (*cpki.Document, error) {
	t.pkiDocCacheLock.RLock()
	defer t.pkiDocCacheLock.RUnlock()
	if doc, exists := t.pkiDocCache[epoch]; exists {
		return doc, nil
	}

	// If the requested epoch is not cached, return the current document
	t.pkidocMutex.RLock()
	currentDoc := t.pkidoc
	t.pkidocMutex.RUnlock()

	if currentDoc != nil {
		return currentDoc, nil
	}

	return nil, errors.New("no PKI document available for the requested epoch")
}

// GetServices returns all services matching the specified capability name.
//
// This method searches the current PKI document for services that provide
// the specified capability. Services in Katzenpost are identified by their
// capability names (e.g., "echo", "courier", "keyserver").
//
// Parameters:
//   - capability: The name of the service capability to search for
//
// Returns:
//   - []*common.ServiceDescriptor: Slice of all matching service descriptors
//   - error: Error if no services with the capability are found
//
// Example:
//
//	// Find all courier services
//	couriers, err := client.GetServices("courier")
//	if err != nil {
//		log.Fatal("No courier services available:", err)
//	}
//	fmt.Printf("Found %d courier services\n", len(couriers))
func (t *ThinClient) GetServices(capability string) ([]*common.ServiceDescriptor, error) {
	doc := t.PKIDocument()
	descriptors := common.FindServices(capability, doc)
	if len(descriptors) == 0 {
		return nil, errors.New("error, GetService failure, service not found in pki doc")
	}
	return descriptors, nil
}

// GetService returns a randomly selected service matching the specified capability.
//
// This method is a convenience wrapper around GetServices() that randomly
// selects one service from all available services with the given capability.
// This provides automatic load balancing across available service instances.
//
// Parameters:
//   - serviceName: The name of the service capability to find
//
// Returns:
//   - *common.ServiceDescriptor: A randomly selected service descriptor
//   - error: Error if no services with the capability are found
//
// Example:
//
//	// Get a random courier service for load balancing
//	courier, err := client.GetService("courier")
//	if err != nil {
//		log.Fatal("No courier service available:", err)
//	}
//	fmt.Printf("Using courier: %s\n", courier.Name)
func (t *ThinClient) GetService(serviceName string) (*common.ServiceDescriptor, error) {
	serviceDescriptors, err := t.GetServices(serviceName)
	if err != nil {
		return nil, err
	}
	return serviceDescriptors[rand.NewMath().Intn(len(serviceDescriptors))], nil
}

// NewMessageID generates a new cryptographically random message identifier.
//
// Message IDs are used to correlate requests with responses in both legacy
// and channel APIs. Each message should have a unique ID to prevent
// confusion and enable proper event correlation.
//
// Returns:
//   - *[MessageIDLength]byte: A new random message ID
//
// Panics:
//   - If the random number generator fails
func (t *ThinClient) NewMessageID() *[MessageIDLength]byte {
	id := new([MessageIDLength]byte)
	_, err := rand.Reader.Read(id[:])
	if err != nil {
		panic(err)
	}
	return id
}

// NewSURBID generates a new Single Use Reply Block identifier.
//
// SURB IDs are used in the legacy API to correlate reply messages with
// their original requests. Each SURB should have a unique ID.
//
// Returns:
//   - *[sConstants.SURBIDLength]byte: A new random SURB ID
func (t *ThinClient) NewSURBID() *[sConstants.SURBIDLength]byte {
	return common.NewSURBID()
}

// NewQueryID generates a new cryptographically random query identifier.
//
// Query IDs are used in the channel API to correlate channel operation
// requests with their responses. Each query should have a unique ID.
//
// Returns:
//   - *[QueryIDLength]byte: A new random query ID
//
// Panics:
//   - If the random number generator fails
func (t *ThinClient) NewQueryID() *[QueryIDLength]byte {
	id := new([QueryIDLength]byte)
	_, err := rand.Reader.Read(id[:])
	if err != nil {
		panic(err)
	}
	return id
}

// SendMessageWithoutReply sends a fire-and-forget message using the legacy API.
//
// DEPRECATED: This method is part of the legacy API. New applications should
// use the Pigeonhole Channel API (CreateWriteChannel, WriteChannel, etc.) which
// provides better reliability, ordering guarantees, and state management.
//
// This method sends a message without any reply capability. The message is
// encapsulated in a Sphinx packet and sent through the mixnet, but no response
// can be received. This is suitable for notifications or one-way communication.
//
// Requirements:
//   - The daemon must be connected to the mixnet (IsConnected() == true)
//   - The destination service must be available in the current PKI document
//
// Parameters:
//   - payload: Message data to send
//   - destNode: Hash of the destination service's identity key
//   - destQueue: Queue ID of the destination service
//
// Returns:
//   - error: Any error encountered during message preparation or sending
//
// Example:
//
//	// Find an echo service
//	echoService, err := client.GetService("echo")
//	if err != nil {
//		return err
//	}
//
//	// Send a fire-and-forget message
//	destNode := hash.Sum256(echoService.MixDescriptor.IdentityKey)
//	destQueue := echoService.RecipientQueueID
//	err = client.SendMessageWithoutReply([]byte("Hello"), &destNode, destQueue)
func (t *ThinClient) SendMessageWithoutReply(payload []byte, destNode *[32]byte, destQueue []byte) error {
	// Check if we're in offline mode
	if !t.isConnected {
		return errors.New("cannot send message in offline mode - daemon not connected to mixnet")
	}

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

// SendMessage sends a message with reply capability using the legacy API.
//
// DEPRECATED: This method is part of the legacy API. New applications should
// use the Pigeonhole Channel API (CreateWriteChannel, WriteChannel, etc.) which
// provides better reliability, ordering guarantees, and state management.
//
// This method sends a message with a Single Use Reply Block (SURB) that allows
// the destination to send a reply. The method is asynchronous - it only blocks
// until the daemon receives the send request, not until the message is actually
// transmitted or a reply is received.
//
// To receive replies, applications must monitor events from EventSink() and
// look for MessageReplyEvent instances with matching SURB IDs.
//
// Requirements:
//   - The daemon must be connected to the mixnet (IsConnected() == true)
//   - The destination service must be available in the current PKI document
//   - A unique SURB ID must be provided for reply correlation
//
// Parameters:
//   - surbID: Unique identifier for correlating replies (use NewSURBID())
//   - payload: Message data to send
//   - destNode: Hash of the destination service's identity key
//   - destQueue: Queue ID of the destination service
//
// Returns:
//   - error: Any error encountered during message preparation or sending
//
// Example:
//
//	// Create event sink to receive replies
//	eventSink := client.EventSink()
//	defer client.StopEventSink(eventSink)
//
//	// Send message with reply capability
//	surbID := client.NewSURBID()
//	echoService, _ := client.GetService("echo")
//	destNode := hash.Sum256(echoService.MixDescriptor.IdentityKey)
//	err := client.SendMessage(surbID, []byte("Hello"), &destNode, echoService.RecipientQueueID)
//
//	// Wait for reply in event loop
//	for event := range eventSink {
//		if reply, ok := event.(*MessageReplyEvent); ok {
//			if bytes.Equal(reply.SURBID[:], surbID[:]) {
//				fmt.Printf("Reply: %s\n", reply.Payload)
//				break
//			}
//		}
//	}
func (t *ThinClient) SendMessage(surbID *[sConstants.SURBIDLength]byte, payload []byte, destNode *[32]byte, destQueue []byte) error {
	if surbID == nil {
		return errors.New("surbID cannot be nil")
	}

	// Check if we're in offline mode
	if !t.isConnected {
		return errors.New("cannot send message in offline mode - daemon not connected to mixnet")
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

// BlockingSendMessage sends a message and blocks until a reply is received.
//
// DEPRECATED: This method is part of the legacy API. New applications should
// use the Pigeonhole Channel API (CreateWriteChannel, WriteChannel, etc.) which
// provides better reliability, ordering guarantees, and state management.
//
// This method provides a synchronous request-response pattern by automatically
// generating a SURB ID, sending the message, and waiting for the reply. It
// blocks until either a reply is received or the context times out.
//
// This is convenient for simple request-response interactions but lacks the
// advanced features of the Pigeonhole Channel API such as message ordering,
// channel persistence, and offline operation support.
//
// Requirements:
//   - The daemon must be connected to the mixnet (IsConnected() == true)
//   - The destination service must be available in the current PKI document
//   - A context with appropriate timeout should be provided
//
// Parameters:
//   - ctx: Context for cancellation and timeout control (recommended: 30s timeout)
//   - payload: Message data to send
//   - destNode: Hash of the destination service's identity key
//   - destQueue: Queue ID of the destination service
//
// Returns:
//   - []byte: Reply payload from the destination service
//   - error: Any error encountered during sending or while waiting for reply
//
// Example:
//
//	// Send message to echo service and wait for reply
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//
//	echoService, err := client.GetService("echo")
//	if err != nil {
//		return err
//	}
//
//	destNode := hash.Sum256(echoService.MixDescriptor.IdentityKey)
//	reply, err := client.BlockingSendMessage(ctx, []byte("Hello"),
//		&destNode, echoService.RecipientQueueID)
//	if err != nil {
//		return err
//	}
//
//	fmt.Printf("Echo reply: %s\n", reply)
func (t *ThinClient) BlockingSendMessage(ctx context.Context, payload []byte, destNode *[32]byte, destQueue []byte) ([]byte, error) {
	if ctx == nil {
		return nil, errContextCannotBeNil
	}

	// Check if we're in offline mode
	if !t.isConnected {
		return nil, errors.New("cannot send message in offline mode - daemon not connected to mixnet")
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
			// Ignore garbage collection events
		case *ConnectionStatusEvent:
			if !v.IsConnected {
				panic(errConnectionLost)
			}
		case *NewDocumentEvent:
			// Ignore PKI document updates
		case *MessageSentEvent:
			// Ignore message sent events
		case *MessageReplyEvent:
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

// SendReliableMessage sends a message with automatic retransmission (ARQ).
//
// DEPRECATED: This method is part of the legacy API. New applications should
// use the Pigeonhole Channel API (CreateWriteChannel, WriteChannel, etc.) which
// provides better reliability, ordering guarantees, and state management.
//
// This method implements Automatic Repeat reQuest (ARQ) functionality, where
// the message is automatically retransmitted until an acknowledgment is received
// or the maximum retry limit is reached. This provides better reliability than
// basic SendMessage but is still inferior to the Pigeonhole Channel API.
//
// The method is asynchronous - it returns immediately after initiating the
// reliable send process. Applications should monitor events to track the
// final outcome of the transmission.
//
// Requirements:
//   - The daemon must be connected to the mixnet (IsConnected() == true)
//   - The destination service must support ARQ acknowledgments
//   - A unique message ID must be provided for tracking
//
// Parameters:
//   - messageID: Unique identifier for tracking this message (use NewMessageID())
//   - payload: Message data to send
//   - destNode: Hash of the destination service's identity key
//   - destQueue: Queue ID of the destination service
//
// Returns:
//   - error: Any error encountered during message preparation or initial sending
//
// Example:
//
//	// Send reliable message with ARQ
//	messageID := client.NewMessageID()
//	echoService, err := client.GetService("echo")
//	if err != nil {
//		return err
//	}
//
//	destNode := hash.Sum256(echoService.MixDescriptor.IdentityKey)
//	err = client.SendReliableMessage(messageID, []byte("Important message"),
//		&destNode, echoService.RecipientQueueID)
//
//	// Monitor events for final outcome
//	eventSink := client.EventSink()
//	defer client.StopEventSink(eventSink)
//	// ... handle MessageSentEvent and MessageReplyEvent
func (t *ThinClient) SendReliableMessage(messageID *[MessageIDLength]byte, payload []byte, destNode *[32]byte, destQueue []byte) error {
	// Check if we're in offline mode
	if !t.isConnected {
		return errors.New("cannot send reliable message in offline mode - daemon not connected to mixnet")
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

	return t.writeMessage(req)
}

// BlockingSendReliableMessage sends a message with ARQ and blocks until completion.
//
// DEPRECATED: This method is part of the legacy API. New applications should
// use the Pigeonhole Channel API (CreateWriteChannel, WriteChannel, etc.) which
// provides better reliability, ordering guarantees, and state management.
//
// This method combines reliable message sending with synchronous operation by
// implementing Automatic Repeat reQuest (ARQ) and blocking until either the
// message is successfully acknowledged or the maximum retry limit is reached.
// It provides the highest reliability available in the legacy API.
//
// The method blocks until the complete ARQ process finishes, which may take
// significant time depending on network conditions and retry configuration.
//
// Requirements:
//   - The daemon must be connected to the mixnet (IsConnected() == true)
//   - The destination service must support ARQ acknowledgments
//   - A unique message ID must be provided for tracking
//   - A context with appropriate timeout should be provided
//
// Parameters:
//   - ctx: Context for cancellation and timeout control (recommended: 60s+ timeout)
//   - messageID: Unique identifier for tracking this message (use NewMessageID())
//   - payload: Message data to send
//   - destNode: Hash of the destination service's identity key
//   - destQueue: Queue ID of the destination service
//
// Returns:
//   - []byte: Reply payload from the destination service (if any)
//   - error: Any error encountered during the reliable send process
//
// Example:
//
//	// Send reliable message and wait for completion
//	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
//	defer cancel()
//
//	messageID := client.NewMessageID()
//	echoService, err := client.GetService("echo")
//	if err != nil {
//		return err
//	}
//
//	destNode := hash.Sum256(echoService.MixDescriptor.IdentityKey)
//	reply, err := client.BlockingSendReliableMessage(ctx, messageID,
//		[]byte("Critical message"), &destNode, echoService.RecipientQueueID)
//	if err != nil {
//		log.Printf("Reliable send failed: %v", err)
//		return err
//	}
//
//	fmt.Printf("Reliable send completed, reply: %s\n", reply)
func (t *ThinClient) BlockingSendReliableMessage(ctx context.Context, messageID *[MessageIDLength]byte, payload []byte, destNode *[32]byte, destQueue []byte) (reply []byte, err error) {
	if ctx == nil {
		return nil, errContextCannotBeNil
	}

	// Check if we're in offline mode
	if !t.isConnected {
		return nil, errors.New("cannot send reliable message in offline mode - daemon not connected to mixnet")
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
			return nil, fmt.Errorf("message reply error: %s", ThinClientErrorToString(reply.ErrorCode))
		}
		return reply.Payload, nil
	case <-t.HaltCh():
		return nil, errHalting
	}

	// unreachable
}

/****

NEW PIGEONHOLE CHANNEL API

****/

// CreateWriteChannel creates a new Pigeonhole write channel for sending messages.
//
// This method creates a new communication channel using the Pigeonhole protocol,
// which provides reliable, ordered message delivery. The channel is created with
// fresh cryptographic capabilities that allow writing messages to the channel
// and sharing read access with other parties.
//
// The returned capabilities have the following purposes:
//   - ReadCap: Can be shared with others to allow them to read messages from this channel
//   - WriteCap: Should be stored securely for channel persistence and resumption
//   - ChannelID: Used for subsequent operations on this channel
//
// Channel operations work in offline mode (when daemon is not connected to mixnet),
// allowing applications to prepare messages even without network connectivity.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//
// Returns:
//   - uint16: Channel ID for subsequent operations
//   - *bacap.ReadCap: Read capability that can be shared with message recipients
//   - *bacap.WriteCap: Write capability for channel persistence and resumption
//   - error: Any error encountered during channel creation
//
// Example:
//
//	ctx := context.Background()
//	channelID, readCap, writeCap, err := client.CreateWriteChannel(ctx)
//	if err != nil {
//		log.Fatal("Failed to create write channel:", err)
//	}
//
//	// Share readCap with Bob so he can read messages
//	// Store writeCap for channel resumption after restart
//	fmt.Printf("Created channel %d\n", channelID)
func (t *ThinClient) CreateWriteChannel(ctx context.Context) (uint16, *bacap.ReadCap, *bacap.WriteCap, error) {
	if ctx == nil {
		return 0, nil, nil, errContextCannotBeNil
	}

	queryID := t.NewQueryID()
	req := &Request{
		CreateWriteChannel: &CreateWriteChannel{
			QueryID: queryID,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return 0, nil, nil, err
	}

	for {
		var event Event
		select {
		case <-ctx.Done():
			return 0, nil, nil, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return 0, nil, nil, errHalting
		}

		switch v := event.(type) {
		case *CreateWriteChannelReply:
			if v.QueryID == nil {
				t.log.Debugf("CreateWriteChannel: Received CreateWriteChannelReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("CreateWriteChannel: Received CreateWriteChannelReply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return 0, nil, nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.ChannelID, v.ReadCap, v.WriteCap, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// CreateReadChannel creates a read channel from a read capability.
//
// This method creates a channel for reading messages using a read capability
// that was obtained from the creator of a write channel. The read capability
// allows access to messages written to the corresponding write channel.
//
// Read channels maintain their own state independent of the write channel,
// allowing multiple readers to consume messages at their own pace. Each
// reader tracks its own position in the message sequence.
//
// Like other channel operations, this works in offline mode, allowing
// applications to set up channels even when the daemon is not connected
// to the mixnet.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - readCap: Read capability obtained from the channel creator
//
// Returns:
//   - uint16: Channel ID for subsequent read operations
//   - error: Any error encountered during channel creation
//
// Example:
//
//	// Bob creates a read channel using Alice's read capability
//	ctx := context.Background()
//	channelID, err := client.CreateReadChannel(ctx, readCap)
//	if err != nil {
//		log.Fatal("Failed to create read channel:", err)
//	}
//
//	// Now Bob can read messages from Alice's channel
//	fmt.Printf("Created read channel %d\n", channelID)
func (t *ThinClient) CreateReadChannel(ctx context.Context, readCap *bacap.ReadCap) (uint16, error) {
	if ctx == nil {
		return 0, errContextCannotBeNil
	}
	if readCap == nil {
		return 0, errors.New("readCap cannot be nil")
	}
	queryID := t.NewQueryID()

	req := &Request{
		CreateReadChannel: &CreateReadChannel{
			QueryID: queryID,
			ReadCap: readCap,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return 0, err
	}

	for {
		var event Event
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return 0, errHalting
		}

		switch v := event.(type) {
		case *CreateReadChannelReply:
			if v.QueryID == nil {
				t.log.Debugf("CreateReadChannel: Received CreateReadChannelReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("CreateReadChannel: Received CreateReadChannelReply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return 0, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.ChannelID, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// WriteChannel prepares a message for writing to a Pigeonhole channel.
//
// This method performs the first step of the two-phase channel write process:
// it prepares the cryptographic payload that will be sent through the mixnet.
// The actual transmission is performed separately using SendChannelQuery().
//
// This separation allows for:
//   - State management and persistence between preparation and transmission
//   - Retry logic and error recovery
//   - Offline operation (preparation works without mixnet connectivity)
//
// The method validates the payload size against the configured Pigeonhole
// geometry limits and returns all information needed to complete the write
// operation, including state for resumption after interruption.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - channelID: Channel ID returned by CreateWriteChannel or ResumeWriteChannel
//   - payload: Message data to write (must not exceed MaxPlaintextPayloadLength)
//
// Returns:
//   - *WriteChannelReply: Contains prepared payload and state information
//   - error: Any error encountered during preparation
//
// Example:
//
//	message := []byte("Hello, Bob!")
//	writeReply, err := client.WriteChannel(ctx, channelID, message)
//	if err != nil {
//		log.Fatal("Failed to prepare write:", err)
//	}
//
//	// Now send the prepared message
//	destNode, destQueue, _ := client.GetCourierDestination()
//	messageID := client.NewMessageID()
//	_, err = client.SendChannelQueryAwaitReply(ctx, channelID,
//		writeReply.SendMessagePayload, destNode, destQueue, messageID)
func (t *ThinClient) WriteChannel(ctx context.Context, channelID uint16, payload []byte) (*WriteChannelReply, error) {
	if ctx == nil {
		return nil, errContextCannotBeNil
	}

	queryID := t.NewQueryID()

	// Validate payload size against pigeonhole geometry
	if len(payload) > t.cfg.PigeonholeGeometry.MaxPlaintextPayloadLength {
		return nil, fmt.Errorf("payload size %d exceeds maximum allowed size %d", len(payload), t.cfg.PigeonholeGeometry.MaxPlaintextPayloadLength)
	}

	req := &Request{
		WriteChannel: &WriteChannel{
			ChannelID: channelID,
			QueryID:   queryID,
			Payload:   payload,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
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
		// match our queryID
		case *WriteChannelReply:
			if v.QueryID == nil {
				t.log.Debugf("WriteChannel: Received WriteChannelReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("WriteChannel: Received WriteChannelReply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// ResumeWriteChannel resumes a write channel from a previous session.
//
// This method allows applications to restore a write channel after a restart
// or interruption by providing the write capability and message index that
// were saved from a previous session. This enables persistent communication
// channels that survive application restarts.
//
// The write capability and message index should be obtained from:
//   - CreateWriteChannelReply.WriteCap and CreateWriteChannelReply.NextMessageIndex
//   - WriteChannelReply.NextMessageIndex from previous write operations
//
// After resumption, the channel can be used normally with WriteChannel()
// and other channel operations.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - writeCap: Write capability from the original channel creation
//   - messageBoxIndex: Message index to resume from (typically the next index to write);
//     if set to nil then the channel will start from the beginning.
//
// Returns:
//   - uint16: Channel ID for subsequent operations on the resumed channel
//   - error: Any error encountered during resumption
//
// Example:
//
//	// During application shutdown, save these values persistently:
//	// writeCap (from CreateWriteChannelReply)
//	// nextMessageIndex (from last WriteChannelReply)
//
//	// After restart, resume the channel:
//	channelID, err := client.ResumeWriteChannel(ctx, writeCap, nextMessageIndex)
//	if err != nil {
//		log.Fatal("Failed to resume write channel:", err)
//	}
//
//	// Continue using the channel normally
//	message := []byte("Resumed channel message")
//	writeReply, err := client.WriteChannel(ctx, channelID, message)
func (t *ThinClient) ResumeWriteChannel(
	ctx context.Context,
	writeCap *bacap.WriteCap,
	messageBoxIndex *bacap.MessageBoxIndex) (uint16, error) {

	if ctx == nil {
		return 0, errContextCannotBeNil
	}
	if writeCap == nil {
		return 0, errors.New("writeCap cannot be nil")
	}
	queryID := t.NewQueryID()

	req := &Request{
		ResumeWriteChannel: &ResumeWriteChannel{
			QueryID:         queryID,
			WriteCap:        writeCap,
			MessageBoxIndex: messageBoxIndex,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return 0, err
	}
	for {
		var event Event
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return 0, errHalting
		}

		switch v := event.(type) {
		// match our queryID
		case *ResumeWriteChannelReply:
			if v.QueryID == nil {
				t.log.Debugf("ResumeWriteChannel: Received ResumeWriteChannelReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("ResumeWriteChannel: Received ResumeWriteChannelReply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return 0, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.ChannelID, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// ResumeWriteChannelQuery resumes a write channel with a specific query state.
//
// This method provides more granular resumption control than ResumeWriteChannel
// by allowing the application to resume from a specific query state, including
// the envelope descriptor and hash. This is useful when resuming from a partially
// completed write operation that was interrupted during transmission.
//
// This method is typically used when an application has saved the complete state
// from a WriteChannelReply and wants to resume from that exact point, including
// any pending query state.
//
// All parameters are required for this method, unlike the basic ResumeWriteChannel
// which only requires the write capability and message index.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - writeCap: Write capability from the original channel creation
//   - messageBoxIndex: Exact message index to resume from
//   - envelopeDescriptor: Envelope descriptor from the interrupted operation
//   - envelopeHash: Hash of the envelope from the interrupted operation
//
// Returns:
//   - uint16: Channel ID for subsequent operations on the resumed channel
//   - error: Any error encountered during resumption
//
// Example:
//
//	// During interruption, save complete state from WriteChannelReply:
//	// writeCap, messageBoxIndex, envelopeDescriptor, envelopeHash
//
//	// Resume with complete query state:
//	channelID, err := client.ResumeWriteChannelQuery(ctx, writeCap,
//		messageBoxIndex, envelopeDescriptor, envelopeHash)
//	if err != nil {
//		log.Fatal("Failed to resume write channel query:", err)
//	}
//
//	// Channel is now ready to continue from the exact interrupted state
func (t *ThinClient) ResumeWriteChannelQuery(
	ctx context.Context,
	writeCap *bacap.WriteCap,
	messageBoxIndex *bacap.MessageBoxIndex,
	envelopeDescriptor []byte,
	envelopeHash *[32]byte) (uint16, error) {

	if ctx == nil {
		return 0, errContextCannotBeNil
	}
	if writeCap == nil {
		return 0, errors.New("writeCap cannot be nil")
	}
	queryID := t.NewQueryID()

	req := &Request{
		ResumeWriteChannelQuery: &ResumeWriteChannelQuery{
			QueryID:            queryID,
			WriteCap:           writeCap,
			MessageBoxIndex:    messageBoxIndex,
			EnvelopeDescriptor: envelopeDescriptor,
			EnvelopeHash:       envelopeHash,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return 0, err
	}
	for {
		var event Event
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return 0, errHalting
		}

		switch v := event.(type) {
		// match our queryID
		case *ResumeWriteChannelQueryReply:
			if v.QueryID == nil {
				t.log.Debugf("ResumeWriteChannel: Received ResumeWriteChannelReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("ResumeWriteChannel: Received ResumeWriteChannelReply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return 0, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.ChannelID, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// ReadChannel prepares a read query for a Pigeonhole channel.
//
// This method performs the first step of the two-phase channel read process:
// it prepares the cryptographic query that will be sent through the mixnet
// to retrieve the next message from the channel. The actual transmission is
// performed separately using SendChannelQuery() or SendChannelQueryAwaitReply().
//
// Note that the last two parameters are useful if you want to send two read
// queries to the same Box id in order to retrieve two different replies. Our
// current sharding scheme ensures that two storage replicas will store a copy
// of the Box we are interested in reading. Thus we can optionally select the
// specific storage replica to query.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - channelID: Channel ID returned by CreateReadChannel or ResumeReadChannel
//   - messageBoxIndex: Optional specific message index to read (nil for next message)
//   - replyIndex: Optional specific reply index within the message (nil for default)
//
// Returns:
//   - *ReadChannelReply: Contains prepared query payload and state information
//   - error: Any error encountered during preparation
//
// Example:
//
//	// Read the next message in sequence
//	readReply, err := client.ReadChannel(ctx, channelID, nil, nil)
//	if err != nil {
//		log.Fatal("Failed to prepare read:", err)
//	}
//
//	// Send the prepared query
//	destNode, destQueue, _ := client.GetCourierDestination()
//	messageID := client.NewMessageID()
//	replyPayload, err := client.SendChannelQueryAwaitReply(ctx, channelID,
//		readReply.SendMessagePayload, destNode, destQueue, messageID)
func (t *ThinClient) ReadChannel(ctx context.Context, channelID uint16, messageBoxIndex *bacap.MessageBoxIndex, replyIndex *uint8) (*ReadChannelReply, error) {
	if ctx == nil {
		return nil, errContextCannotBeNil
	}

	queryID := t.NewQueryID()

	req := &Request{
		ReadChannel: &ReadChannel{
			ChannelID:       channelID,
			QueryID:         queryID,
			MessageBoxIndex: messageBoxIndex,
			ReplyIndex:      replyIndex,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
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
		// match our queryID
		case *ReadChannelReply:
			if v.QueryID == nil {
				t.log.Debugf("ReadChannel: Received ReadChannelReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// ResumeReadChannel resumes a read channel from a previous session.
//
// This method allows applications to restore a read channel after a restart
// or interruption by providing the read capability and position information
// that were saved from a previous session. This enables persistent communication
// channels that survive application restarts.
//
// The read capability should be obtained from the channel creator, and the
// position information should be saved from previous read operations to
// maintain proper message sequencing.
//
// After resumption, the channel can be used normally with ReadChannel()
// and other channel operations.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - readCap: Read capability obtained from the channel creator
//   - nextMessageIndex: Message index to resume from. If set to nil then the channel
//     will start from the beginning index value indicated by the readCap.
//   - replyIndex: Reply index within the message (nil for default)
//
// Returns:
//   - uint16: Channel ID for subsequent operations on the resumed channel
//   - error: Any error encountered during resumption
//
// Example:
//
//	// During application shutdown, save these values persistently:
//	// readCap (from channel creator)
//	// nextMessageIndex (from last ReadChannelReply)
//	// replyIndex (from last ReadChannelReply)
//
//	// After restart, resume the channel:
//	channelID, err := client.ResumeReadChannel(ctx, readCap,
//		nextMessageIndex, replyIndex)
//	if err != nil {
//		log.Fatal("Failed to resume read channel:", err)
//	}
//
//	// Continue reading messages normally
//	readReply, err := client.ReadChannel(ctx, channelID, nil, nil)
func (t *ThinClient) ResumeReadChannel(
	ctx context.Context,
	readCap *bacap.ReadCap,
	nextMessageIndex *bacap.MessageBoxIndex,
	replyIndex *uint8) (uint16, error) {

	queryID := t.NewQueryID()
	req := &Request{
		ResumeReadChannel: &ResumeReadChannel{
			QueryID:          queryID,
			ReadCap:          readCap,
			NextMessageIndex: nextMessageIndex,
			ReplyIndex:       replyIndex,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)
	err := t.writeMessage(req)
	if err != nil {
		return 0, err
	}
	for {
		var event Event
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return 0, errHalting
		}

		switch v := event.(type) {
		// match our queryID
		case *ResumeReadChannelReply:
			if v.QueryID == nil {
				t.log.Debugf("ResumeReadChannel: Received ResumeReadChannelReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("ResumeReadChannel: Received ResumeReadChannelReply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return 0, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.ChannelID, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// ResumeReadChannelQuery resumes a read channel with a specific query state.
//
// This method provides more granular resumption control than ResumeReadChannel
// by allowing the application to resume from a specific query state, including
// the envelope descriptor and hash. This is useful when resuming from a partially
// completed read operation that was interrupted during transmission.
//
// This method is typically used when an application has saved the complete state
// from a ReadChannelReply and wants to resume from that exact point, including
// any pending query state.
//
// Most parameters are required for this method. Only replyIndex may be nil,
// in which case it defaults to 0 (the first reply in the message).
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - readCap: Read capability obtained from the channel creator
//   - nextMessageIndex: Exact message index to resume from (required)
//   - replyIndex: Reply index within the message (nil defaults to 0)
//   - envelopeDescriptor: Envelope descriptor from the interrupted operation (required)
//   - envelopeHash: Hash of the envelope from the interrupted operation (required)
//
// Returns:
//   - uint16: Channel ID for subsequent operations on the resumed channel
//   - error: Any error encountered during resumption
//
// Example:
//
//	// During interruption, save complete state from ReadChannelReply:
//	// readCap, nextMessageIndex, replyIndex, envelopeDescriptor, envelopeHash
//
//	// Resume with complete query state:
//	channelID, err := client.ResumeReadChannelQuery(ctx, readCap,
//		nextMessageIndex, replyIndex, envelopeDescriptor, envelopeHash)
//	if err != nil {
//		log.Fatal("Failed to resume read channel query:", err)
//	}
//
//	// Channel is now ready to continue from the exact interrupted state
func (t *ThinClient) ResumeReadChannelQuery(
	ctx context.Context,
	readCap *bacap.ReadCap,
	nextMessageIndex *bacap.MessageBoxIndex,
	replyIndex *uint8,
	envelopeDescriptor []byte,
	envelopeHash *[32]byte) (uint16, error) {

	queryID := t.NewQueryID()
	req := &Request{
		ResumeReadChannelQuery: &ResumeReadChannelQuery{
			QueryID:            queryID,
			ReadCap:            readCap,
			NextMessageIndex:   nextMessageIndex,
			ReplyIndex:         replyIndex,
			EnvelopeDescriptor: envelopeDescriptor,
			EnvelopeHash:       envelopeHash,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)
	err := t.writeMessage(req)
	if err != nil {
		return 0, err
	}
	for {
		var event Event
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return 0, errHalting
		}

		switch v := event.(type) {
		// match our queryID
		case *ResumeReadChannelQueryReply:
			if v.QueryID == nil {
				t.log.Debugf("ResumeReadChannelQuery: Received ResumeReadChannelQueryReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("ResumeReadChannelQuery: Received ResumeReadChannelQueryReply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return 0, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.ChannelID, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// CloseChannel closes a Pigeonhole channel and releases its resources.
//
// This method cleanly closes a channel that was created with CreateWriteChannel,
// CreateReadChannel, or any of the Resume methods. Closing a channel releases
// the associated resources in the client daemon and should be called when the
// channel is no longer needed.
//
// After closing a channel, the channel ID becomes invalid and should not be
// used for further operations. Attempting to use a closed channel ID will
// result in errors.
//
// This operation works in both online and offline modes, as it only affects
// local state in the client daemon.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - channelID: Channel ID to close (from Create or Resume operations)
//
// Returns:
//   - error: Any error encountered during channel closure
//
// Example:
//
//	// Create a channel
//	channelID, readCap, writeCap, err := client.CreateWriteChannel(ctx)
//	if err != nil {
//		return err
//	}
//
//	// Use the channel for operations...
//	// ...
//
//	// Clean up when done
//	err = client.CloseChannel(ctx, channelID)
//	if err != nil {
//		log.Printf("Warning: failed to close channel %d: %v", channelID, err)
//	}
//
//	// Store writeCap and readCap for future resumption if needed
func (t *ThinClient) CloseChannel(ctx context.Context, channelID uint16) error {
	if ctx == nil {
		return errContextCannotBeNil
	}

	req := &Request{
		CloseChannel: &CloseChannel{
			ChannelID: channelID,
		},
	}

	return t.writeMessage(req)
}

// SendChannelQuery sends a prepared channel query to the mixnet without waiting for a reply.
//
// This method performs the second step of the two-phase channel operation process.
// It takes a payload prepared by WriteChannel or ReadChannel and transmits it
// through the mixnet to the specified courier service.
//
// This is a fire-and-forget operation - it does not wait for a reply. Use
// SendChannelQueryAwaitReply if you need to wait for and receive the response.
//
// Requirements:
//   - The daemon must be connected to the mixnet (IsConnected() == true)
//   - The payload must be prepared by WriteChannel or ReadChannel
//   - The destination must be obtained from GetCourierDestination()
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - channelID: Channel ID from CreateWriteChannel/CreateReadChannel/Resume operations
//   - payload: Prepared payload from WriteChannel or ReadChannel
//   - destNode: Courier service node hash from GetCourierDestination()
//   - destQueue: Courier service queue ID from GetCourierDestination()
//   - messageID: Unique message identifier for correlation
//
// Returns:
//   - error: Any error encountered during transmission
//
// Example:
//
//	// Prepare a write operation
//	writeReply, err := client.WriteChannel(ctx, channelID, message)
//	if err != nil {
//		return err
//	}
//
//	// Get courier destination
//	destNode, destQueue, err := client.GetCourierDestination()
//	if err != nil {
//		return err
//	}
//
//	// Send without waiting for reply
//	messageID := client.NewMessageID()
//	err = client.SendChannelQuery(ctx, channelID, writeReply.SendMessagePayload,
//		destNode, destQueue, messageID)
func (t *ThinClient) SendChannelQuery(
	ctx context.Context,
	channelID uint16,
	payload []byte,
	destNode *[32]byte,
	destQueue []byte,
	messageID *[MessageIDLength]byte,
) error {

	if ctx == nil {
		return errContextCannotBeNil
	}

	// Check if we're in offline mode
	if !t.isConnected {
		return errors.New("cannot send channel query in offline mode - daemon not connected to mixnet")
	}

	req := &Request{
		SendChannelQuery: &SendChannelQuery{
			MessageID:         messageID,
			ChannelID:         &channelID,
			Payload:           payload,
			DestinationIdHash: destNode,
			RecipientQueueID:  destQueue,
		},
	}

	return t.writeMessage(req)
}

// SendChannelQueryAwaitReply sends a prepared channel query and waits for the reply.
//
// This method performs the second step of the two-phase channel operation process
// and blocks until a reply is received or the context times out. It combines
// sending the prepared payload with waiting for and returning the response.
//
// This is the most commonly used method for channel operations as it provides
// a complete request-response cycle. For fire-and-forget operations, use
// SendChannelQuery instead.
//
// Requirements:
//   - The daemon must be connected to the mixnet (IsConnected() == true)
//   - The payload must be prepared by WriteChannel or ReadChannel
//   - The destination must be obtained from GetCourierDestination()
//
// Parameters:
//   - ctx: Context for cancellation and timeout control (recommended: 30s timeout)
//   - channelID: Channel ID from CreateWriteChannel/CreateReadChannel/Resume operations
//   - payload: Prepared payload from WriteChannel or ReadChannel
//   - destNode: Courier service node hash from GetCourierDestination()
//   - destQueue: Courier service queue ID from GetCourierDestination()
//   - messageID: Unique message identifier for correlation
//
// Returns:
//   - []byte: Response payload from the courier service
//   - error: Any error encountered during transmission or while waiting for reply
//
// Example:
//
//	// Prepare a read operation
//	readReply, err := client.ReadChannel(ctx, channelID, nil, nil)
//	if err != nil {
//		return err
//	}
//
//	// Get courier destination
//	destNode, destQueue, err := client.GetCourierDestination()
//	if err != nil {
//		return err
//	}
//
//	// Send and wait for reply
//	messageID := client.NewMessageID()
//	replyPayload, err := client.SendChannelQueryAwaitReply(ctx, channelID,
//		readReply.SendMessagePayload, destNode, destQueue, messageID)
//	if err != nil {
//		return err
//	}
//
//	// Process the received message
//	fmt.Printf("Received: %s\n", replyPayload)
func (t *ThinClient) SendChannelQueryAwaitReply(
	ctx context.Context,
	channelID uint16,
	payload []byte,
	destNode *[32]byte,
	destQueue []byte,
	messageID *[MessageIDLength]byte,
) ([]byte, error) {

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.SendChannelQuery(ctx, channelID, payload, destNode, destQueue, messageID)
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
		case *ChannelQuerySentEvent:
			if v.MessageID == nil {
				t.log.Debugf("SendChannelQueryAwaitReply: Received ChannelQuerySentEvent with nil MessageID, ignoring")
				continue
			}
			if !bytes.Equal(v.MessageID[:], messageID[:]) {
				t.log.Debugf("SendChannelQueryAwaitReply: Received ChannelQuerySentEvent with mismatched MessageID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			continue
		case *ChannelQueryReplyEvent:
			if v.MessageID == nil {
				t.log.Debugf("SendChannelQueryAwaitReply: Received MessageReplyEvent with nil MessageID, ignoring")
				continue
			}
			if !bytes.Equal(v.MessageID[:], messageID[:]) {
				t.log.Debugf("SendChannelQueryAwaitReply: Received MessageReplyEvent with mismatched MessageID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.Payload, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// GetCourierDestination returns a courier service destination for the current epoch.
//
// This method finds and randomly selects a courier service from the current
// PKI document. Courier services handle Pigeonhole protocol operations,
// storing and retrieving messages for channels. The random selection provides
// automatic load balancing across available courier instances.
//
// The returned destination information is used with SendChannelQuery and
// SendChannelQueryAwaitReply to transmit prepared channel operations to
// the mixnet.
//
// Returns:
//   - *[32]byte: Hash of the courier service's identity key (destination node)
//   - []byte: Queue ID for the courier service
//   - error: Error if no courier services are available
//
// Example:
//
//	// Get courier destination for sending a channel query
//	destNode, destQueue, err := client.GetCourierDestination()
//	if err != nil {
//		log.Fatal("No courier services available:", err)
//	}
//
//	// Use with SendChannelQuery
//	messageID := client.NewMessageID()
//	err = client.SendChannelQuery(ctx, channelID, payload,
//		destNode, destQueue, messageID)
func (t *ThinClient) GetCourierDestination() (*[32]byte, []byte, error) {
	epoch, _, _ := epochtime.Now()
	epochDoc, err := t.PKIDocumentForEpoch(epoch)
	if err != nil {
		return nil, nil, err
	}
	courierServices := common.FindServices("courier", epochDoc)
	if len(courierServices) == 0 {
		return nil, nil, errors.New("no courier services found")
	}
	// Select a random courier service for load distribution
	courierService := courierServices[rand.NewMath().Intn(len(courierServices))]
	destNode := hash.Sum256(courierService.MixDescriptor.IdentityKey)
	destQueue := courierService.RecipientQueueID
	return &destNode, destQueue, nil
}
