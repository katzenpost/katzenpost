// session.go - Wire protocol session.
// Copyright (C) 2017  David Anthony Stainton, Yawning Angel
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

// Package wire implements the Katzenpost wire protocol.
package wire

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/wire/commands"
	"github.com/katzenpost/noise"
)

const (
	// MaxAdditionalDataLength is the maximum length of the additional data
	// sent to the peer as part of the handshake authentication.
	MaxAdditionalDataLength = 255

	maxMsgLen = 1048576
	macLen    = 16
	authLen   = 1 + MaxAdditionalDataLength + 4
)

const (
	stateInit        uint32 = 0
	stateEstablished uint32 = 1
	stateInvalid     uint32 = 2
)

var (
	errInvalidState         = errors.New("wire/session: invalid state")
	errAuthenticationFailed = errors.New("wire/session: authentication failed")
	errMsgSize              = errors.New("wire/session: invalid message size")
)

type authenticateMessage struct {
	ad       []byte
	unixTime uint32
}

func (m *authenticateMessage) ToBytes(b []byte) []byte {
	var zeroBytes [MaxAdditionalDataLength]byte

	if len(m.ad) > MaxAdditionalDataLength {
		panic("wire/session: invalid AuthenticateMessage AD length")
	}

	b = append(b, uint8(len(m.ad)))
	b = append(b, m.ad...)
	b = append(b, zeroBytes[:len(zeroBytes)-len(m.ad)]...)
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[0:], m.unixTime)
	b = append(b, tmp[:]...)

	return b
}

func authenticateMessageFromBytes(b []byte) *authenticateMessage {
	if len(b) != authLen {
		panic("wire/session: invalid AuthenticateMessage")
	}

	adLen := int(b[0])

	m := new(authenticateMessage)
	m.ad = make([]byte, 0, adLen)
	m.ad = append(m.ad, b[1:1+adLen]...)
	m.unixTime = binary.BigEndian.Uint32(b[1+MaxAdditionalDataLength:])

	return m
}

// PeerCredentials is the peer's credentials received durring the authenticated
// key exchange.  By virtue of the Noise Protocol's design, the AdditionalData
// is guaranteed to have been sent from a peer posessing the private component
// of PublicKey.
type PeerCredentials struct {
	AdditionalData []byte
	PublicKey      *ecdh.PublicKey
}

// PeerAuthenticator is the interface used to authenticate the remote peer,
// based on the authenticated key exchange.
type PeerAuthenticator interface {
	// IsPeerValid authenticates the remote peer's credentials, returning true
	// iff the peer is valid.
	IsPeerValid(*PeerCredentials) bool
}

// SessionInterface is the interface used to initialize or teardown a Session
// and send and receive command.Commands.
type SessionInterface interface {
	Initialize(conn net.Conn) error
	SendCommand(cmd commands.Command) error
	RecvCommand() (commands.Command, error)
	Close()
	PeerCredentials() *PeerCredentials
	ClockSkew() time.Duration
}

// Session is a wire protocol session.
type Session struct {
	conn net.Conn

	peerCredentials *PeerCredentials
	authenticator   PeerAuthenticator

	additionalData    []byte
	authenticationKey *ecdh.PrivateKey

	randReader io.Reader
	tx         *noise.CipherState
	rx         *noise.CipherState

	clockSkew   time.Duration
	state       uint32
	isInitiator bool
}

func (s *Session) handshake() error {
	defer func() {
		s.authenticationKey.Reset() // Don't need this anymore, and s has a copy.
		atomic.CompareAndSwapUint32(&s.state, stateInit, stateInvalid)
	}()
	prologue := []byte{0x00}

	// Convert to the noise library's idea of a X25519 key.
	dhKey := noise.DHKey{
		Private: s.authenticationKey.Bytes(),
		Public:  s.authenticationKey.PublicKey().Bytes(),
	}

	// Initialize the Noise library.
	cs := noise.NewCipherSuiteHFS(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b, noise.HFSNewHopeSimple)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Random:        s.randReader,
		Pattern:       noise.HandshakeXXhfs,
		Initiator:     s.isInitiator,
		StaticKeypair: dhKey,
		Prologue:      prologue,
		MaxMsgLen:     maxMsgLen,
	})
	if err != nil {
		return err
	}
	const (
		prologueLen = 1
		keyLen      = 32
		sendALen    = 1824
		sendBLen    = 2176
		msg1Len     = prologueLen + keyLen + sendALen                            // -> (prologue), e, f
		msg2Len     = (keyLen + sendBLen + macLen + keyLen) + (macLen + authLen) // <- e, f, ee, ff, s, es, (auth)
		msg3Len     = (macLen + keyLen) + (macLen + authLen)                     // -> s, se, (auth)
	)

	if s.isInitiator {
		// -> (prologue), e, f
		msg1 := make([]byte, 0, msg1Len)
		msg1 = append(msg1, prologue...)
		msg1, _, _, err = hs.WriteMessage(msg1, nil)
		if err != nil {
			return err
		}
		if _, err = s.conn.Write(msg1); err != nil {
			return err
		}

		// <- e, f, ee, ff, s, es, (auth)
		msg2 := make([]byte, msg2Len)
		if _, err = io.ReadFull(s.conn, msg2); err != nil {
			return err
		}
		now := time.Now()
		rawAuth := make([]byte, 0, authLen)
		rawAuth, _, _, err = hs.ReadMessage(rawAuth, msg2)
		if err != nil {
			return err
		}
		peerAuth := authenticateMessageFromBytes(rawAuth)

		// Authenticate the peer.
		peerAuthenticationKey := new(ecdh.PublicKey)
		if err = peerAuthenticationKey.FromBytes(hs.PeerStatic()); err != nil {
			return err
		}
		s.peerCredentials = &PeerCredentials{
			AdditionalData: peerAuth.ad,
			PublicKey:      peerAuthenticationKey,
		}
		if !s.authenticator.IsPeerValid(s.peerCredentials) {
			return errAuthenticationFailed
		}

		// Cache the clock skew.
		peerClock := time.Unix(int64(peerAuth.unixTime), 0)
		s.clockSkew = now.Sub(peerClock)

		// -> s, se, (auth)
		ourAuth := &authenticateMessage{ad: s.additionalData}
		rawAuth = make([]byte, 0, authLen)
		rawAuth = ourAuth.ToBytes(rawAuth)
		msg3 := make([]byte, 0, msg3Len)
		msg3, s.tx, s.rx, err = hs.WriteMessage(msg3, rawAuth)
		if err != nil {
			return err
		}
		if _, err = s.conn.Write(msg3); err != nil {
			return err
		}
	} else {
		// -> (prologue), e, f
		msg1 := make([]byte, msg1Len)
		if _, err = io.ReadFull(s.conn, msg1); err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(prologue, msg1[0:1]) != 1 {
			return errors.New("wire/session: unsupported protocol version")
		}
		msg1 = msg1[1:]
		if _, _, _, err = hs.ReadMessage(nil, msg1); err != nil {
			return err
		}

		// <- e, f, ee, ff, s, es, (auth)
		ourAuth := &authenticateMessage{
			ad:       s.additionalData,
			unixTime: uint32(time.Now().Unix()), // XXX: Add noise.
		}
		rawAuth := make([]byte, 0, authLen)
		rawAuth = ourAuth.ToBytes(rawAuth)
		msg2 := make([]byte, 0, msg2Len)
		msg2, _, _, err = hs.WriteMessage(msg2, rawAuth)
		if err != nil {
			return err
		}
		if _, err = s.conn.Write(msg2); err != nil {
			return err
		}

		// -> s, se, (auth)
		msg3 := make([]byte, msg3Len)
		rawAuth = make([]byte, 0, authLen)
		if _, err = io.ReadFull(s.conn, msg3); err != nil {
			return err
		}
		rawAuth, s.rx, s.tx, err = hs.ReadMessage(rawAuth, msg3)
		if err != nil {
			return err
		}
		peerAuth := authenticateMessageFromBytes(rawAuth)

		// Authenticate the peer.
		peerAuthenticationKey := new(ecdh.PublicKey)
		if err = peerAuthenticationKey.FromBytes(hs.PeerStatic()); err != nil {
			return err
		}
		s.peerCredentials = &PeerCredentials{
			AdditionalData: peerAuth.ad,
			PublicKey:      peerAuthenticationKey,
		}
		if !s.authenticator.IsPeerValid(s.peerCredentials) {
			return errAuthenticationFailed
		}
	}

	atomic.StoreUint32(&s.state, stateEstablished)
	return nil
}

func (s *Session) finalizeHandshake() error {
	if s.isInitiator {
		// Initiator: The peer will send a NoOp command immediately upon
		// completing the handshake.
		cmd, err := s.RecvCommand()
		if err != nil {
			return err
		}
		if _, ok := cmd.(*commands.NoOp); !ok {
			// Protocol violation, the peer sent something other than a NoOp.
			return errInvalidState
		}
		return nil
	}

	// Responder: The peer is authenticated at this point, so dispatch
	// a NoOp so the peer can distinguish authentication failures.
	noOpCmd := &commands.NoOp{}
	return s.SendCommand(noOpCmd)
}

// Initialize takes an establised net.Conn, and binds it to a Session, and
// conducts the wire protocol handshake.
func (s *Session) Initialize(conn net.Conn) error {
	if atomic.LoadUint32(&s.state) != stateInit {
		return errInvalidState
	}
	s.conn = conn

	if err := s.handshake(); err != nil {
		return err
	}
	if err := s.finalizeHandshake(); err != nil {
		atomic.StoreUint32(&s.state, stateInvalid)
		return err
	}
	return nil
}

// SendCommand sends the wire protocol command cmd.
func (s *Session) SendCommand(cmd commands.Command) error {
	if atomic.LoadUint32(&s.state) != stateEstablished {
		return errInvalidState
	}

	// XXX: Figure out if padding is actually needed, and append it as
	// neccecary.  As it stands right now, it might not be, as the `message`
	// command's various responses all have identical sizes.

	// Derive the Ciphertext length.
	pt := cmd.ToBytes()
	ctLen := macLen + len(pt)
	if ctLen > maxMsgLen {
		return errMsgSize
	}

	// Build the CiphertextHeader.
	var ctHdr [4]byte
	binary.BigEndian.PutUint32(ctHdr[:], uint32(ctLen))
	toSend := make([]byte, 0, macLen+4+ctLen)
	toSend = s.tx.Encrypt(toSend, nil, ctHdr[:])

	// Build the Ciphertext.
	toSend = s.tx.Encrypt(toSend, nil, pt)
	s.tx.Rekey()

	_, err := s.conn.Write(toSend)
	if err != nil {
		// All write errors are fatal.
		atomic.StoreUint32(&s.state, stateInvalid)
	}
	return err
}

// RecvCommand receives a wire protocol command off the network.
func (s *Session) RecvCommand() (commands.Command, error) {
	cmd, err := s.recvCommandImpl()
	if err != nil {
		// All receive errors are fatal.
		atomic.StoreUint32(&s.state, stateInvalid)
	}
	return cmd, err
}

func (s *Session) recvCommandImpl() (commands.Command, error) {
	if atomic.LoadUint32(&s.state) != stateEstablished {
		return nil, errInvalidState
	}

	// Read, decrypt and parse the CiphertextHeader.
	var ctHdrCt [macLen + 4]byte
	if _, err := io.ReadFull(s.conn, ctHdrCt[:]); err != nil {
		return nil, err
	}
	ctHdr, err := s.rx.Decrypt(nil, nil, ctHdrCt[:])
	if err != nil {
		return nil, err
	}
	ctLen := binary.BigEndian.Uint32(ctHdr[:])
	if ctLen < macLen || ctLen > maxMsgLen {
		return nil, errMsgSize
	}

	// Read and decrypt the Ciphertext.
	ct := make([]byte, ctLen)
	if _, err := io.ReadFull(s.conn, ct); err != nil {
		return nil, err
	}
	pt, err := s.rx.Decrypt(nil, nil, ct)
	if err != nil {
		return nil, err
	}
	s.rx.Rekey()

	// Parse and return the command.
	return commands.FromBytes(pt)
}

// Close terminates a session.
func (s *Session) Close() {
	// The Noise library doesn't have a way to explcitly clear cryptographic
	// state.  Without an underlying crypto break, Rekey() is backtracking
	// resistant.
	if s.tx != nil {
		s.tx.Rekey()
	}
	if s.rx != nil {
		s.rx.Rekey()
	}
	s.authenticationKey.Reset()
	if s.conn != nil {
		s.conn.Close()
	}
	atomic.StoreUint32(&s.state, stateInvalid)
}

// PeerCredentials returns the peer's credentials.  This call MUST only be
// called from a session that has succesfully completed Initialize().
func (s *Session) PeerCredentials() (*PeerCredentials, error) {
	if atomic.LoadUint32(&s.state) != stateEstablished {
		return nil, errors.New("wire/session: PeerCredentials() call in invalid state")
	}
	return s.peerCredentials, nil
}

// ClockSkew returns the approximate clock skew based on the responder's
// timestamp received as part of the handshake.  This call MUST only be called
// from a session that has successfully completed Initialize(), and the peer is
// the responder.
func (s *Session) ClockSkew() time.Duration {
	if !s.isInitiator {
		panic("wire/session: ClockSkew() call by responder")
	}
	if atomic.LoadUint32(&s.state) != stateEstablished {
		panic("wire/session: ClockSkew() call in invalid state")
	}
	return s.clockSkew
}

// NewSession creates a new Session.
func NewSession(cfg *SessionConfig, isInitiator bool) (*Session, error) {
	if cfg.Authenticator == nil {
		return nil, errors.New("wire/session: missing Authenticator")
	}
	if len(cfg.AdditionalData) > MaxAdditionalDataLength {
		return nil, errors.New("wire/session: oversized AdditionalData")
	}
	if cfg.AuthenticationKey == nil {
		return nil, errors.New("wire/session: missing AuthenticationKey")
	}
	if cfg.RandomReader == nil {
		return nil, errors.New("wire/session: missing RandomReader")
	}

	s := &Session{
		authenticator:     cfg.Authenticator,
		additionalData:    cfg.AdditionalData,
		authenticationKey: new(ecdh.PrivateKey),
		randReader:        cfg.RandomReader,
		isInitiator:       isInitiator,
		state:             stateInit,
	}
	if err := s.authenticationKey.FromBytes(cfg.AuthenticationKey.Bytes()); err != nil {
		panic("wire/session: BUG: failed to copy authentication key: " + err.Error())
	}

	return s, nil
}

// SessionConfig is the configuration used to create new Sessions.
type SessionConfig struct {
	// Authenticator is the PeerAuthenticator instance that will be used to
	// authenticate the remote peer for the newly created Session.
	Authenticator PeerAuthenticator

	// AdditionalData is the additional data that will be passed to the peer
	// as part of the wire protocol handshake, the length of which MUST be less
	// than or equal to MaxAdditionalDataLength.
	AdditionalData []byte

	// AuthenticationKey is the static long term authentication key used to
	// authenticate with the remote peer.
	AuthenticationKey *ecdh.PrivateKey

	// RandomReader is a cryptographic entropy source.
	RandomReader io.Reader
}
