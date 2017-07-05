// common.go - Common code for clients and servers of our wire protocol.
// Copyright (C) 2017  David Anthony Stainton
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package common

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/katzenpost/core/utils"
	"github.com/katzenpost/noise"
	"github.com/op/go-logging"
	"golang.org/x/crypto/ed25519"
)

var log = logging.MustGetLogger("session")

const (
	messagePayloadSize = 30 // XXX fix me

	// MaxPayloadSize is the maximum payload size permitted by wire protocol
	MaxPayloadSize = 65515

	// messageOverhead is the number of bytes before the message's payload
	messageOverhead = 4

	// messageMessageOverhead is the number of bytes before the
	// inner message's message
	messageMessageOverhead = 6

	// messageMaxSize is the size of a message
	messageMaxSize = MaxPayloadSize + messageOverhead

	// messageCiphertextMaxSize is the size of the encrypted message
	// that is the "ciphertext" element of the Ciphertext struct
	messageCiphertextMaxSize = messageMaxSize + 16

	// messageMessageSize is the size of the inner message of
	// the "message" command
	messageMessageSize = MaxPayloadSize + 5 // XXX fix me

	// messageAckSize
	messageAckSize = messageMessageSize

	// SphinxPacketSize is the Sphinx packet size
	SphinxPacketSize = 32768 // XXX: Yawning fix me

	// SURBIdSize is the size of a Sphinx SURB ID
	SURBIdSize = 16 // XXX: Yawning fix me

	// ed25519KeySize is the size of an ed25519 key
	ed25519KeySize = 32

	// ed25519SignatureSize is the size of an ed25519 signature
	ed25519SignatureSize = 64

	// blake2bHashSize is the size of a blake2b hash
	blake2bHashSize = 32

	// additionalDataSize is the size of additional data
	// in the authentication command
	additionalDataSize = 64

	// unixTimeSize is the size of a unix timestamp
	unixTimeSize = 4

	// authCmdSize is the size of the authenticate command
	authCmdSize = ed25519KeySize + ed25519SignatureSize + additionalDataSize + unixTimeSize

	// reserved is a reserved section of the serialized commands
	reserved = byte(0)

	// noOpSize is the size of a serialized noOp command
	noOpSize = uint16(10)

	// disconnectSize is the size of a serialized disconnect command
	disconnectSize = uint16(10)

	// PrologueSize is the size of our noise handshake prologue
	prologueSize = 1

	// serverHandshakeMessageSize is the size of the server handshake message
	// it's our one byte prologue + an ed25519 key + 16 byte MAC
	serverHandshakeMessageSize = 49

	// clientHandshakeMessageSize is the size of the client handshake message
	// it's our one byte prologue + an ed25519 key
	clientHandshakeMessageSize = 33

	// retreiveMessageSize is the size of the retreiveMessage command, a 32 bit sequence
	retreiveMessageSize = 4

	// messageTypeMessage specifies that the MessageCommand is to transmit
	// a message instead of an ACKnowledgement
	messageTypeMessage = 0

	// messageTypeAck specifies that the MessageCommand is to transmit
	// a message ACKnowledgement
	messageTypeAck = 1

	// command IDs
	noOp            commandID = 0
	disconnect      commandID = 1
	authenticate    commandID = 2
	sendPacket      commandID = 3
	retreiveMessage commandID = 16
	message         commandID = 17
)

// Wire Protocol Command ID type
type commandID byte

var errInvalidCommand = errors.New("invalid wire protocol command")

// Command is the common interface exposed by all message
// command structures.
type Command interface {
	toBytes() []byte
}

type NoOpCommand struct{}

func (c NoOpCommand) toBytes() []byte {
	out := make([]byte, messageOverhead+int(noOpSize))
	out[0] = byte(noOp)
	return out
}

type DisconnectCommand struct{}

func (c DisconnectCommand) toBytes() []byte {
	out := make([]byte, messageOverhead+int(disconnectSize))
	out[0] = byte(disconnect)
	return out
}

type AuthenticateCommand struct {
	PublicKey      [ed25519KeySize]byte
	Signature      [ed25519SignatureSize]byte
	AdditionalData [additionalDataSize]byte
	UnixTime       uint32
}

func (c AuthenticateCommand) toBytes() []byte {
	out := make([]byte, messageOverhead+authCmdSize)
	out[0] = byte(authenticate)
	out[1] = reserved
	binary.BigEndian.PutUint16(out[2:4], authCmdSize)
	copy(out[4:], c.PublicKey[:])
	copy(out[4+ed25519KeySize:], c.Signature[:])
	copy(out[4+ed25519KeySize+ed25519SignatureSize:], c.AdditionalData[:])
	binary.BigEndian.PutUint32(out[4+ed25519KeySize+ed25519SignatureSize+additionalDataSize:], c.UnixTime)
	return out
}

type SendPacketCommand struct {
	SphinxPacket [SphinxPacketSize]byte
}

func (c SendPacketCommand) toBytes() []byte {
	out := make([]byte, messageOverhead+SphinxPacketSize)
	out[0] = byte(sendPacket)
	out[1] = reserved
	binary.BigEndian.PutUint16(out[2:4], SphinxPacketSize)
	copy(out[4:], c.SphinxPacket[:])
	return out
}

type RetrieveMessageCommand struct {
	Sequence uint32
}

func (c RetrieveMessageCommand) toBytes() []byte {
	out := make([]byte, messageOverhead+retreiveMessageSize)
	out[0] = byte(retreiveMessage)
	out[1] = reserved
	binary.BigEndian.PutUint32(out[2:6], retreiveMessageSize)
	return out
}

type MessageMessageCommand struct {
	QueueSizeHint    uint8
	Sequence         uint32
	EncryptedPayload [messagePayloadSize]byte
}

func (c MessageMessageCommand) toBytes() []byte {
	out := make([]byte, messageOverhead+messageMessageOverhead+messagePayloadSize)
	out[0] = byte(message)
	out[1] = reserved
	// out[2:6] is written as msg_length in the spec
	binary.BigEndian.PutUint16(out[2:4], uint16(0)) // XXX fix me
	// out[4:] inner messageACK struct fields follow:
	out[4] = messageTypeMessage
	out[5] = c.QueueSizeHint
	binary.BigEndian.PutUint32(out[6:10], c.Sequence)
	copy(out[10:], c.EncryptedPayload[:])
	return out
}

type MessageAckCommand struct {
	QueueSizeHint    uint8
	Sequence         uint32
	SURBId           [SURBIdSize]byte
	EncryptedPayload [messagePayloadSize]byte
}

func (c MessageAckCommand) toBytes() []byte {
	out := make([]byte, messageOverhead+retreiveMessageSize)
	out[0] = byte(message)
	out[1] = reserved
	// out[2:6] is written as msg_length in the spec
	binary.BigEndian.PutUint32(out[2:6], messageAckSize)
	// out[6:] inner messageACK struct fields follow:
	out[6] = messageTypeAck
	out[7] = c.QueueSizeHint
	binary.BigEndian.PutUint32(out[8:12], c.Sequence)
	copy(out[12:12+SURBIdSize], c.SURBId[:])
	copy(out[12+SURBIdSize:], c.EncryptedPayload[:])
	return out
}

// CommandToCiphertextBytes converts Command
// structures to ciphertext bytes
func CommandToCiphertextBytes(cs *noise.CipherState, cmd Command) (ciphertext []byte) {
	raw := cmd.toBytes()

	ciphertext = cs.Encrypt(ciphertext, nil, raw)
	cs.Rekey()
	return ciphertext
}

// fromBytes converts a byte slice to a command structure
func fromBytes(raw []byte) (Command, error) {
	cmdId := raw[0]
	raw = raw[1:]
	switch commandID(cmdId) {
	case noOp:
		if len(raw) != int(noOpSize)+messageOverhead-1 {
			return nil, errInvalidCommand
		}
		if !utils.CtIsZero(raw) {
			return nil, errInvalidCommand
		}
		return NoOpCommand{}, nil
	case disconnect:
		if len(raw) != int(disconnectSize)+messageOverhead-1 {
			return nil, errInvalidCommand
		}
		if !utils.CtIsZero(raw) {
			return nil, errInvalidCommand
		}
		return DisconnectCommand{}, nil
	case authenticate:
		if len(raw) != authCmdSize+messageOverhead-1 {
			return nil, errInvalidCommand
		}
		if raw[0] != byte(0) {
			return nil, errInvalidCommand
		}
		cmd := AuthenticateCommand{}
		//size := binary.BigEndian.Uint16(raw[1:3]) // XXX should we bother with this?
		raw = raw[3:]
		copy(cmd.PublicKey[:], raw[:ed25519KeySize])
		copy(cmd.Signature[:], raw[ed25519KeySize:ed25519SignatureSize+ed25519KeySize])
		copy(cmd.AdditionalData[:], raw[ed25519KeySize+ed25519SignatureSize:])
		cmd.UnixTime = binary.BigEndian.Uint32(raw[ed25519KeySize+ed25519SignatureSize+additionalDataSize:])
		return cmd, nil
	case sendPacket:
		if len(raw) != SphinxPacketSize+messageOverhead-1 {
			return nil, errInvalidCommand
		}
		if raw[0] != byte(0) {
			return nil, errInvalidCommand
		}
		cmd := SendPacketCommand{} // XXX fix me
		//size := binary.BigEndian.Uint16(raw[1:3]) // XXX should we bother with this?
		raw = raw[3:]
		copy(cmd.SphinxPacket[:], raw)
		return cmd, nil
	case retreiveMessage:
		if len(raw) != int(retreiveMessageSize)+messageOverhead-1 {
			return nil, errInvalidCommand
		}
		if raw[0] != byte(0) {
			return nil, errInvalidCommand
		}
		raw = raw[3:]
		cmd := RetrieveMessageCommand{
			Sequence: binary.BigEndian.Uint32(raw),
		}
		return cmd, nil
	case message:
		// XXX todo: fix me
		if raw[0] != byte(0) { // reserved field
			return nil, errInvalidCommand
		}
		//messageSize := binary.BigEndian.Uint16(raw[1:3]) // msg_length is wire-protocol.txt spec
		messageType := raw[3] // type field of Message struct in end_to_end.txt spec
		queueSizeHint := raw[4]
		sequence := binary.BigEndian.Uint32(raw[5:9])

		switch byte(messageType) {
		case messageTypeMessage:
			cmd := MessageMessageCommand{
				QueueSizeHint: queueSizeHint,
				Sequence:      sequence,
			}
			copy(cmd.EncryptedPayload[:], raw[9:9+messagePayloadSize])
			return cmd, nil
		case messageTypeAck:
			cmd := MessageAckCommand{
				QueueSizeHint: queueSizeHint,
				Sequence:      sequence,
			}
			copy(cmd.SURBId[:], raw[9:9+SURBIdSize])
			copy(cmd.EncryptedPayload[:], raw[9+SURBIdSize:])
			return cmd, nil
		}
		return nil, errInvalidCommand
	default:
		return nil, errInvalidCommand
	}
}

// FromCiphertextBytes converts ciphertext
// bytes to Command structures
func FromCiphertextBytes(cs *noise.CipherState, ciphertext []byte) (Command, error) {
	var plaintext []byte
	var err error
	plaintext, err = cs.Decrypt(plaintext, nil, ciphertext)
	if err != nil {
		log.Debugf("FromCiphertextBytes fail: Decrypt: %s", err)
		return nil, err
	}
	cs.Rekey()
	cmd, err := fromBytes(plaintext)
	if err != nil {
		log.Debugf("FromCiphertextBytes fail: fromBytes: %s", err)
		return nil, err
	}
	return Command(cmd), err
}

// ReceiveCommand reads the next wire protocol command
// from the connection and decrypts and returns the
// deserialized command structure
func ReceiveCommand(cs *noise.CipherState, conn io.Reader) (Command, error) {
	rawLen := make([]byte, 2)
	_, err := io.ReadFull(conn, rawLen)
	if err != nil {
		log.Debugf("ReceiveCommand fail: 1st ReadFull: %s", err)
		return nil, err
	}

	ciphertextLen := binary.BigEndian.Uint16(rawLen[0:2])
	ciphertext := make([]byte, ciphertextLen)
	_, err = io.ReadFull(conn, ciphertext)
	if err != nil {
		log.Debugf("ReceiveCommand fail: 2nd ReadFull: %s", err)
		return nil, err
	}
	cmd, err := FromCiphertextBytes(cs, ciphertext)
	if err != nil {
		log.Debugf("ReceiveCommand fail: FromCiphertextBytes: %s", err)
		return nil, err
	}
	return cmd, err
}

// SendPacket
func SendPacket(cmd Command, cs *noise.CipherState, conn io.Writer) error {
	ciphertext := CommandToCiphertextBytes(cs, cmd)
	ciphertextLen := len(ciphertext)
	packet := make([]byte, ciphertextLen+2) // add two for a uint16 big endian length field
	binary.BigEndian.PutUint16(packet[0:2], uint16(ciphertextLen))
	copy(packet[2:], ciphertext)

	count, err := conn.Write(packet)
	if err != nil {
		return err
	}
	if count != len(packet) {
		return fmt.Errorf("failed to send entire packet: %d != %d", count, len(packet))
	}
	return nil
}

type ClientAuthorizer interface {
	IsClientValid(id []byte, publicKey *[32]byte) bool
}

// Options is used to configure various properties of the client session
type Options struct {
	// Noise Handshake Prologue value represents our wire protocol version
	// and currently should be set to a zero byte
	PrologueVersion byte

	// ClientAuthorizer is used by Providers to authorize their clients
	ClientAuthorizer ClientAuthorizer
}

var defaultSessionOptions = Options{
	PrologueVersion: byte(0),
}

// Config is non-optional configuration for a Session
type Config struct {
	// Initiator indicates whether this session is used by
	// a client or a server
	Initiator bool

	// Identifier is used as a Provider, Mix or Client identifier
	Identifier []byte // max length additionalDataSize

	// Random is a source of random data used by the Noise library
	Random io.Reader

	// LongtermEd25519PublicKey is the longterm Ed25519 public key
	LongtermEd25519PublicKey ed25519.PublicKey

	// LongtermEd25519PrivateKey is the longterm Ed25519 private key
	LongtermEd25519PrivateKey ed25519.PrivateKey
}

// Session is the server side of our
// noise based wire protocol as specified in the
// Panoramix Mix Network Wire Protocol Specification
type Session struct {
	options        *Options
	config         *Config
	conn           io.ReadWriteCloser
	noiseConfig    noise.Config
	handshakeState *noise.HandshakeState
	cipherState0   *noise.CipherState
	cipherState1   *noise.CipherState
	doneChan       chan bool
}

// New creates a new session.
func New(config *Config, options *Options) *Session {
	session := Session{}
	session.doneChan = make(chan bool, 1)
	if options == nil {
		session.options = &defaultSessionOptions
	} else {
		session.options = options
	}
	session.config = config
	session.noiseConfig = noise.Config{}
	session.noiseConfig.Random = config.Random
	session.noiseConfig.Initiator = config.Initiator
	session.noiseConfig.Prologue = []byte{session.options.PrologueVersion}
	session.noiseConfig.Pattern = noise.HandshakeNN
	session.noiseConfig.CipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	session.noiseConfig.EphemeralKeypair = noise.DH25519.GenerateKeypair(config.Random)
	session.handshakeState = noise.NewHandshakeState(session.noiseConfig)
	return &session
}

// serverHandshake performs the noise based handshake exchange
// with the server
func (s *Session) serverHandshake() error {
	log.Debug("server initiates handshake")
	var err error

	receivedHsMsg := make([]byte, clientHandshakeMessageSize)
	_, err = io.ReadFull(s.conn, receivedHsMsg)
	if err != nil {
		return err
	}
	log.Debug("server received client handshake message")

	if receivedHsMsg[0] != s.options.PrologueVersion {
		return fmt.Errorf("received client prologue doesn't match %d != %d", s.options.PrologueVersion, receivedHsMsg[0])
	}

	serverHsResult, _, _, err := s.handshakeState.ReadMessage(nil, receivedHsMsg[1:])
	if err != nil {
		return err
	}
	if len(serverHsResult) != 0 {
		return fmt.Errorf("server decoded incorrect message length: %d != %d", len(serverHsResult), 0)
	}

	var hsMsg []byte
	serverHsMsg := make([]byte, serverHandshakeMessageSize)
	hsMsg, s.cipherState0, s.cipherState1 = s.handshakeState.WriteMessage(nil, nil)
	serverHsMsg[0] = s.options.PrologueVersion
	copy(serverHsMsg[1:], hsMsg)

	count, err := s.conn.Write(serverHsMsg)
	if err != nil {
		return err
	}
	if count != len(serverHsMsg) {
		return fmt.Errorf("server did not send correct handshake length bytes: %d != %d", count, len(serverHsMsg))
	}
	log.Debug("server handshake completed")

	return nil
}

// clientHandshake performs the noise based handshake exchange
// with the server
func (s *Session) clientHandshake() error {
	log.Debug("client initiates handshake")
	var err error

	clientHsMsg := make([]byte, 1)
	hsMsg, _, _ := s.handshakeState.WriteMessage(nil, nil)

	clientHsMsg[0] = s.options.PrologueVersion
	clientHsMsg = append(clientHsMsg, hsMsg...)

	count, err := s.conn.Write(clientHsMsg)
	if err != nil {
		return err
	}
	if count != len(clientHsMsg) {
		return fmt.Errorf("client did not send correct handshake length bytes: %d != %d", count, len(clientHsMsg))
	}
	log.Debug("client sent handshake message")

	receivedHsMsg := make([]byte, serverHandshakeMessageSize)
	_, err = io.ReadFull(s.conn, receivedHsMsg)
	if err != nil {
		return err
	}
	log.Debug("client received server handshake message")

	if receivedHsMsg[0] != s.options.PrologueVersion {
		return fmt.Errorf("received server prologue doesn't match %d != %d", s.options.PrologueVersion, receivedHsMsg[0])
	}

	// decode hs message from server
	var clientHsResult []byte
	clientHsResult, s.cipherState0, s.cipherState1, err = s.handshakeState.ReadMessage(nil, receivedHsMsg[1:])
	if err != nil {
		return err
	}
	if len(clientHsResult) != 0 {
		return fmt.Errorf("client decoded incorrect message length: %d != %d", len(clientHsResult), 0)
	}

	log.Debug("client handshake completed")
	return nil
}

// handshake performs the appropriate handshake,
// either client or server
func (s *Session) handshake() (err error) {
	if s.noiseConfig.Initiator {
		err = s.clientHandshake()
	} else {
		err = s.serverHandshake()
	}
	if err != nil {
		return err
	}
	return
}

// generateAuthenticateCommand returns an AuthenticateCommand
func (s *Session) generateAuthenticateCommand() *AuthenticateCommand {
	// produce an Ed25519 signature covering:
	// h | byte(len(additional_data)) | additional_data
	unsignedMessage := make([]byte, blake2bHashSize+1+additionalDataSize)
	additionalData := make([]byte, additionalDataSize)
	copy(additionalData, s.config.Identifier)
	copy(unsignedMessage, s.handshakeState.ChannelBinding())
	unsignedMessage[blake2bHashSize] = uint8(len(s.config.Identifier))
	copy(unsignedMessage[blake2bHashSize+1:], additionalData)
	signature := ed25519.Sign(s.config.LongtermEd25519PrivateKey, unsignedMessage)
	authCmd := AuthenticateCommand{
		UnixTime: uint32(time.Now().Unix()),
	}
	copy(authCmd.PublicKey[:], []byte(s.config.LongtermEd25519PublicKey))
	copy(authCmd.Signature[:], signature)
	copy(authCmd.AdditionalData[:], additionalData)
	return &authCmd
}

// verifyAuthSignature verifies an authentication command's signature
func (s *Session) verifyAuthSignature(auth *AuthenticateCommand) bool {
	authMsg := make([]byte, blake2bHashSize+1+additionalDataSize)
	additionalData := make([]byte, additionalDataSize)
	copy(additionalData, auth.AdditionalData[:])
	copy(authMsg, s.handshakeState.ChannelBinding())
	authMsg[blake2bHashSize] = uint8(bytes.Index(additionalData, []byte{0}))
	copy(authMsg[blake2bHashSize+1:], additionalData)
	return ed25519.Verify(ed25519.PublicKey(auth.PublicKey[:]), authMsg, auth.Signature[:])
}

// authenticate performs the authentication
// for either the server or client
func (s *Session) authenticate() (err error) {
	if s.noiseConfig.Initiator {
		cmd, err := s.Receive()
		if err != nil {
			return err
		}
		auth, ok := cmd.(AuthenticateCommand)
		if !ok {
			log.Error("received a non-authenticate command")
			err := s.Close()
			if err != nil {
				log.Error(err)
			}
			err = errors.New("received a non-authenticate command")
			return err
		}
		if !s.verifyAuthSignature(&auth) {
			log.Error("failed to verify authenticator command's signature")
			err = errors.New("failed to verify authenticator command's signature")
			return err
		}
		authCmd := s.generateAuthenticateCommand()
		err = s.Send(authCmd)
		if err != nil {
			return err
		}
	} else {
		authCmd := s.generateAuthenticateCommand()
		err = s.Send(authCmd)
		if err != nil {
			return err
		}
		cmd, err := s.Receive()
		if err != nil {
			return err
		}
		auth, ok := cmd.(AuthenticateCommand)
		if !ok {
			log.Error("received a non-authenticate command")
			err := s.Close()
			if err != nil {
				log.Error(err)
			}
			err = errors.New("received a non-authenticate command")
			return err
		}
		if !s.verifyAuthSignature(&auth) {
			log.Error("failed to verify authenticator command's signature")
			err = errors.New("failed to verify authenticator command's signature")
			return err
		}
		if s.options.ClientAuthorizer != nil {
			s.options.ClientAuthorizer.IsClientValid(auth.AdditionalData[:], &auth.PublicKey)
		}
	}
	return
}

// Initiate receives a handshake from our client.
// This is the beginning of our wire protocol state machine
// where the noise handshake is received and responded to.
func (s *Session) Initiate(conn io.ReadWriteCloser) (err error) {
	s.conn = conn
	err = s.handshake()
	if err != nil {
		return err
	}
	err = s.authenticate()
	return err
}

// Receive receives a Command
func (s *Session) Receive() (Command, error) {
	var err error
	var cmd Command
	if s.noiseConfig.Initiator {
		log.Debug("client Receive")
		cmd, err = ReceiveCommand(s.cipherState0, s.conn)
	} else {
		log.Debug("server Receive")
		cmd, err = ReceiveCommand(s.cipherState1, s.conn)
	}
	return cmd, err
}

// Send sends a payload.
func (s *Session) Send(cmd Command) (err error) {
	if s.noiseConfig.Initiator {
		log.Debug("client Send")
		err = SendPacket(cmd, s.cipherState1, s.conn)
	} else {
		log.Debug("server Send")
		err = SendPacket(cmd, s.cipherState0, s.conn)
	}
	return err
}

// Close closes the session.
func (s *Session) Close() error {
	s.cipherState0 = nil
	s.cipherState1 = nil
	s.doneChan <- true
	return s.conn.Close()
}

// NotifyClosed return a channel which receives a bool
// when Close is called
func (s *Session) NotifyClosed() <-chan bool {
	return s.doneChan
}
