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
//
// Note: ARQ (Automatic Repeat reQuest) is now used exclusively for the new Pigeonhole API.
//
// ## Pigeonhole Channel API
//
// For more information about this API please see our API documentation, here:
// https://katzenpost.network/docs/client_integration/#pigeonhole-channel-api
//
// The new Pigeonhole protocol provides the following messages and their corresponding
// replies/events:
//   - NewKeypair
//   - EncryptRead
//   - EncryptWrite
//   - StartResendingEncryptedMessage
//   - CancelResendingEncryptedMessage
//
// The old Pigeonhole protocol API provides:
//
//   - CreateWriteChannel: Create a new channel for sending messages
//   - CreateReadChannel: Create a channel for receiving messages
//   - WriteChannel: Prepare a message for transmission
//   - ReadChannel: Prepare a query to read the next message
//   - SendChannelQuery: Send prepared queries to the mixnet
//   - ResumeWriteChannel/ResumeReadChannel: Resume channels after restart
//
// # Configuration
//
// The thin client requires configuration specifying:
//   - Network and address of the client daemon
//   - Sphinx geometry parameters
//   - Pigeonhole geometry parameters
//
// See the testdata/thinclient.toml file for an example configuration.
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

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client2/common"
	"github.com/katzenpost/katzenpost/client2/config"
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

	// Pigeonhole ARQ error sentinels
	// These errors can be returned by StartResendingEncryptedMessage and can be
	// checked using errors.Is() for specific error handling.

	// ErrBoxIDNotFound indicates that the requested box ID was not found on the replica.
	// This typically occurs when attempting to read from a non-existent mailbox.
	ErrBoxIDNotFound = errors.New("box ID not found")

	// ErrInvalidBoxID indicates that the box ID format is invalid.
	ErrInvalidBoxID = errors.New("invalid box ID")

	// ErrInvalidSignature indicates that the signature verification failed.
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrDatabaseFailure indicates that the replica encountered a database error.
	ErrDatabaseFailure = errors.New("database failure")

	// ErrInvalidPayload indicates that the payload data is invalid.
	ErrInvalidPayload = errors.New("invalid payload")

	// ErrStorageFull indicates that the replica's storage capacity has been exceeded.
	ErrStorageFull = errors.New("storage full")

	// ErrReplicaInternalError indicates an internal error on the replica.
	ErrReplicaInternalError = errors.New("replica internal error")

	// ErrInvalidEpoch indicates that the epoch is invalid or expired.
	ErrInvalidEpoch = errors.New("invalid epoch")

	// ErrReplicationFailed indicates that replication to other replicas failed.
	ErrReplicationFailed = errors.New("replication failed")

	// ErrInvalidEnvelope indicates that the courier envelope format is invalid.
	ErrInvalidEnvelope = errors.New("invalid envelope")

	// ErrCacheCorruption indicates that cache data corruption was detected.
	ErrCacheCorruption = errors.New("cache corruption")

	// ErrPropagationError indicates an error propagating the request to replicas.
	ErrPropagationError = errors.New("propagation error")

	// ErrInternalError indicates an internal client error.
	ErrInternalError = errors.New("internal error")

	// ErrMKEMDecryptionFailed indicates that MKEM decryption failed.
	// This occurs when the MKEM envelope cannot be decrypted with any of the replica keys.
	ErrMKEMDecryptionFailed = errors.New("MKEM decryption failed")

	// ErrBACAPDecryptionFailed indicates that BACAP decryption failed.
	// This occurs when the BACAP payload cannot be decrypted or signature verification fails.
	ErrBACAPDecryptionFailed = errors.New("BACAP decryption failed")

	// ErrStartResendingCancelled indicates that a StartResendingEncryptedMessage
	// operation was cancelled via CancelResendingEncryptedMessage before completion.
	ErrStartResendingCancelled = errors.New("start resending cancelled")
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

	// Legacy: These maps were previously used by BlockingSendReliableMessage (now removed).
	// They may be removed in a future cleanup if no longer needed.
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

			/**  New Pigeonhole API **/

		case message.NewKeypairReply != nil:
			select {
			case t.eventSink <- message.NewKeypairReply:
				continue
			case <-t.HaltCh():
				return
			}
		case message.EncryptReadReply != nil:
			select {
			case t.eventSink <- message.EncryptReadReply:
				continue
			case <-t.HaltCh():
				return
			}
		case message.EncryptWriteReply != nil:
			select {
			case t.eventSink <- message.EncryptWriteReply:
				continue
			case <-t.HaltCh():
				return
			}
		case message.StartResendingEncryptedMessageReply != nil:
			select {
			case t.eventSink <- message.StartResendingEncryptedMessageReply:
				continue
			case <-t.HaltCh():
				return
			}
		case message.CancelResendingEncryptedMessageReply != nil:
			select {
			case t.eventSink <- message.CancelResendingEncryptedMessageReply:
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
