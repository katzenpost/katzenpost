// Copyright (C) 2019, 2021 Yawning Angel. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package nyquist

import (
	"crypto/rand"
	"encoding"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/schemes"

	"github.com/katzenpost/nyquist/cipher"
	"github.com/katzenpost/nyquist/dh"
	"github.com/katzenpost/nyquist/hash"
	"github.com/katzenpost/nyquist/pattern"
	"github.com/katzenpost/nyquist/seec"
)

const (
	// DefaultMaxMessageSize is the default maximum message size.
	DefaultMaxMessageSize = 65535

	// PreSharedKeySize is the size of the pre-shared symmetric key.
	PreSharedKeySize = 32

	protocolPrefix  = "Noise"
	invalidProtocol = "[invalid protocol]"
)

var (
	errTruncatedE = errors.New("nyquist/HandshakeState/ReadMessage/e: truncated message")
	errTruncatedS = errors.New("nyquist/HandshakeState/ReadMessage/s: truncated message")
	errMissingS   = errors.New("nyquist/HandshakeState/WriteMessage/s: s not set")

	errMissingPSK = errors.New("nyquist/New: missing or excessive PreSharedKey(s)")
	errBadPSK     = errors.New("nyquist/New: malformed PreSharedKey(s)")
)

// Protocol is a the protocol to be used with a handshake.
type Protocol struct {
	Pattern pattern.Pattern

	DH  dh.DH
	KEM kem.Scheme

	Cipher cipher.Cipher
	Hash   hash.Hash
}

// String returns the string representation of the protocol name.
func (pr *Protocol) String() string {
	if pr.Pattern == nil || pr.Cipher == nil || pr.Hash == nil {
		return invalidProtocol
	}

	var kexStr string
	if pr.Pattern.IsKEM() {
		if pr.KEM == nil || pr.DH != nil {
			return invalidProtocol
		}
		kexStr = pr.KEM.Name()
	} else {
		if pr.KEM != nil || pr.DH == nil {
			return invalidProtocol
		}
		kexStr = pr.DH.String()
	}

	parts := []string{
		protocolPrefix,
		pr.Pattern.String(),
		kexStr,
		pr.Cipher.String(),
		pr.Hash.String(),
	}
	return strings.Join(parts, "_")
}

// NewProtocol returns a Protocol from the provided (case-sensitive) protocol
// name.  Returned protocol objects may be reused across multiple
// HandshakeConfigs.
//
// Note: Only protocols that can be built with the built-in crypto and patterns
// are supported.  Using custom crypto/patterns will require manually building
// a Protocol object.
func NewProtocol(s string) (*Protocol, error) {
	parts := strings.Split(s, "_")
	if len(parts) != 5 || parts[0] != protocolPrefix {
		return nil, ErrProtocolNotSupported
	}

	var pr Protocol
	if pr.Pattern = pattern.FromString(parts[1]); pr.Pattern != nil {
		if pr.Pattern.IsKEM() {
			pr.KEM = schemes.ByName(parts[2])
		} else {
			pr.DH = dh.FromString(parts[2])
		}
	}
	pr.Cipher = cipher.FromString(parts[3])
	pr.Hash = hash.FromString(parts[4])

	if pr.Pattern == nil || (pr.DH == nil && pr.KEM == nil) || pr.Cipher == nil || pr.Hash == nil {
		return nil, ErrProtocolNotSupported
	}

	return &pr, nil
}

// HandshakeConfig is a handshake configuration.
//
// Warning: While the config may contain sensitive material like DH private
// keys or a pre-shared key, sanitizing such things are the responsibility of
// the caller, after the handshake completes (or aborts due to an error).
//
// Altering any of the members of this structure while a handshake is in
// progress will result in undefined behavior.
type HandshakeConfig struct {
	// Protocol is the noise protocol to use for this handshake.
	Protocol *Protocol

	// Prologue is the optional pre-handshake prologue input to be included
	// in the handshake hash.
	Prologue []byte

	// DH is the Diffie-Hellman keys for this handshake.
	DH *DHConfig

	// KEM is the Key Encapsulation Mechanism keys for this handshake.
	KEM *KEMConfig

	// PreSharedKeys is the vector of pre-shared symmetric key for PSK mode
	// handshakes.
	PreSharedKeys [][]byte

	// Rng is the entropy source to be used when entropy is required.
	// If the value is `nil`, `crypto/rand.Reader` will be used.
	Rng io.Reader

	// MaxMessageSize specifies the maximum Noise message size the handshake
	// and session will process or generate.  If the value is `0`,
	// `DefaultMaxMessageSize` will be used.  A negative value will disable
	// the maximum message size enforcement entirely.
	//
	// Warning: Values other than the default is a non-standard extension
	// to the protocol.
	MaxMessageSize int

	// IsInitiator should be set to true if this handshake is in the
	// initiator role.
	IsInitiator bool
}

// DHConfig is the Diffie-Hellman (DH) key configuration of a handshake.
type DHConfig struct {
	// LocalStatic is the local static keypair, if any (`s`).
	LocalStatic dh.Keypair

	// LocalEphemeral is the local ephemeral keypair, if any (`e`).
	LocalEphemeral dh.Keypair

	// RemoteStatic is the remote static public key, if any (`rs`).
	RemoteStatic dh.PublicKey

	// RemoteEphemeral is the remote ephemeral public key, if any (`re`).
	RemoteEphemeral dh.PublicKey

	// Observer is the optional handshake observer.
	Observer HandshakeObserverDH
}

// KEMConfig is the Key Encapsuation Mechanism (KEM) key configuration
// of a handshake.
type KEMConfig struct {
	// LocalStatic is the local static keypair, if any (`s`).
	LocalStatic kem.PrivateKey

	// LocalEphemeral is the local ephemeral keypair, if any (`e`).
	LocalEphemeral kem.PrivateKey

	// RemoteStatic is the remote static public key, if any (`rs`).
	RemoteStatic kem.PublicKey

	// RemoteEphemeral is the remote ephemeral public key, if any (`re`).
	RemoteEphemeral kem.PublicKey

	// Observer is the optional handshake observer.
	Observer HandshakeObserverKEM

	// GenKey is the SEEC GenKey instance to be used to generate
	// entropy for a KEM scheme when required.  If the value is `nil`,
	// `seec.GenKeyPassthrough` will be used.
	GenKey seec.GenKey
}

// HandshakeStatus is the status of a handshake.
//
// Warning: It is the caller's responsibility to sanitize the CipherStates
// if desired.  Altering any of the members of this structure while a handshake
// is in progress will result in undefined behavior.
type HandshakeStatus struct {
	// Err is the error representing the status of the handshake.
	//
	// It will be `nil` if the handshake is in progess, `ErrDone` if the
	// handshake is complete, and any other error if the handshake has failed.
	Err error

	// DH is the Diffie-Hellman public keys of the handshake.
	DH *DHStatus

	// KEM is the Key Encapsulation Mechanism public keys of the handshake.
	KEM *KEMStatus

	// CipherStates is the resulting CipherState pair (`(cs1, cs2)`).
	//
	// Note: To prevent misuse, for one-way patterns `cs2` will be nil.
	CipherStates []*CipherState

	// HandshakeHash is the handshake hash (`h`).  This field is only set
	// once the handshake is completed.
	HandshakeHash []byte
}

// DHStatus is the Diffie-Hellman (DH) status of a handshake.
type DHStatus struct {
	// LocalEphemeral is the local ephemeral public key, if any (`e`).
	LocalEphemeral dh.PublicKey

	// RemoteStatic is the remote static public key, if any (`rs`).
	RemoteStatic dh.PublicKey

	// RemoteEphemeral is the remote ephemeral public key, if any (`re`).
	RemoteEphemeral dh.PublicKey
}

// KEMStatus is the Key Encapsulation Mechanism (KEM) status of a handshake.
type KEMStatus struct {
	// LocalEphemeral is the local ephemeral public key, if any (`e`).
	LocalEphemeral kem.PublicKey

	// RemoteStatic is the remote static public key, if any (`rs`).
	RemoteStatic kem.PublicKey

	// RemoteEphemeral is the remote ephemeral public key, if any (`re`).
	RemoteEphemeral kem.PublicKey
}

// HandshakeObserverDH is a handshake observer for monitoring Diffie-Hellman
// based handshake status.
type HandshakeObserverDH interface {
	// OnPeerPublicKey will be called when a public key is received from
	// the peer, with the handshake pattern token (`pattern.Token_e`,
	// `pattern.Token_s`) and public key.
	//
	// Returning a non-nil error will abort the handshake immediately.
	OnPeerPublicKey(pattern.Token, dh.PublicKey) error
}

// HandshakeObseverKEM is a handshake observer for monitoring Key Encapsulation
// Mechanism based handshake status.
type HandshakeObserverKEM interface {
	// OnPeerPublicKey will be called when a public key is received from
	// the peer, with the handshake pattern token (`pattern.Token_e`,
	// `pattern.Token_s`) and public key.
	//
	// Returning a non-nil error will abort the handshake immediately.
	OnPeerPublicKey(pattern.Token, kem.PublicKey) error
}

func (cfg *HandshakeConfig) getRng() io.Reader {
	if cfg.Rng == nil {
		return rand.Reader
	}
	return cfg.Rng
}

func (cfg *HandshakeConfig) getMaxMessageSize() int {
	if cfg.MaxMessageSize > 0 {
		return cfg.MaxMessageSize
	}
	if cfg.MaxMessageSize == 0 {
		return DefaultMaxMessageSize
	}
	return 0
}

// HandshakeState is the per-handshake state.
type HandshakeState struct {
	cfg *HandshakeConfig

	patterns []pattern.Message

	dh *dhState

	kem     *kemState
	genRand seec.GenRand

	ss *SymmetricState

	status *HandshakeStatus

	patternIndex   int
	pskIndex       int
	maxMessageSize int
	isInitiator    bool
}

type dhState struct {
	impl dh.DH

	s  dh.Keypair
	e  dh.Keypair
	rs dh.PublicKey
	re dh.PublicKey

	pkLen int // aka DHLEN
}

type kemState struct {
	impl kem.Scheme

	s  kem.PrivateKey
	e  kem.PrivateKey
	rs kem.PublicKey
	re kem.PublicKey

	pkLen int
	ctLen int
}

// SymmetricState returns the HandshakeState's encapsulated SymmetricState.
//
// Warning: There should be no reason to call this, ever.
func (hs *HandshakeState) SymmetricState() *SymmetricState {
	return hs.ss
}

// GetStatus returns the HandshakeState's status.
func (hs *HandshakeState) GetStatus() *HandshakeStatus {
	return hs.status
}

// Reset clears the HandshakeState, to prevent future calls.
//
// Warning: If either of the local keypairs were provided by the
// HandshakeConfig, they will be left intact.
func (hs *HandshakeState) Reset() {
	if hs.ss != nil {
		hs.ss.Reset()
		hs.ss = nil
	}
	if hs.cfg.DH != nil && hs.dh != nil {
		if hs.dh.s != nil && hs.dh.s != hs.cfg.DH.LocalStatic {
			// Having a local static key, that isn't from the config currently can't
			// happen, but this is harmless.
			hs.dh.s.DropPrivate()
		}
		if hs.dh.e != nil && hs.dh.e != hs.cfg.DH.LocalEphemeral {
			hs.dh.e.DropPrivate()
		}
	}
	// TODO: Should this set hs.status.Err?
}

func (hs *HandshakeState) onWriteTokenE(dst []byte) []byte {
	if hs.kem != nil {
		return hs.onWriteTokenE_KEM(dst)
	}

	return hs.onWriteTokenE_DH(dst)
}

func (hs *HandshakeState) onReadTokenE(payload []byte) []byte {
	if hs.kem != nil {
		return hs.onReadTokenE_KEM(payload)
	}

	return hs.onReadTokenE_DH(payload)
}

func (hs *HandshakeState) onWriteTokenS(dst []byte) []byte {
	if hs.kem != nil {
		return hs.onWriteTokenS_KEM(dst)
	}

	return hs.onWriteTokenS_DH(dst)
}

func (hs *HandshakeState) onReadTokenS(payload []byte) []byte {
	if hs.kem != nil {
		return hs.onReadTokenS_KEM(payload)
	}

	return hs.onReadTokenS_DH(payload)
}

func (hs *HandshakeState) onTokenPsk() {
	// PSK is validated at handshake creation.
	hs.ss.MixKeyAndHash(hs.cfg.PreSharedKeys[hs.pskIndex])
	hs.pskIndex++
}

func (hs *HandshakeState) onDone(dst []byte) ([]byte, error) {
	hs.patternIndex++
	if hs.patternIndex < len(hs.patterns) {
		return dst, nil
	}

	hs.status.Err = ErrDone
	cs1, cs2 := hs.ss.Split()
	if hs.cfg.Protocol.Pattern.IsOneWay() {
		cs2.Reset()
		cs2 = nil
	}
	hs.status.CipherStates = []*CipherState{cs1, cs2}
	hs.status.HandshakeHash = hs.ss.GetHandshakeHash()

	// This will end up being called redundantly if the developer has any
	// sense at al, but it's cheap foot+gun avoidance.
	hs.Reset()

	return dst, hs.status.Err
}

// WriteMessage processes a write step of the handshake protocol, appending the
// handshake protocol message to dst, and returning the potentially new slice.
//
// Iff the handshake is complete, the error returned will be `ErrDone`.
func (hs *HandshakeState) WriteMessage(dst, payload []byte) ([]byte, error) {
	if hs.status.Err != nil {
		return nil, hs.status.Err
	}

	if hs.isInitiator != (hs.patternIndex&1 == 0) {
		hs.status.Err = ErrOutOfOrder
		return nil, hs.status.Err
	}

	baseLen := len(dst)
	for _, v := range hs.patterns[hs.patternIndex] {
		switch v {
		case pattern.Token_e:
			dst = hs.onWriteTokenE(dst)
		case pattern.Token_s:
			dst = hs.onWriteTokenS(dst)
		case pattern.Token_ee:
			hs.onTokenEE()
		case pattern.Token_es:
			hs.onTokenES()
		case pattern.Token_se:
			hs.onTokenSE()
		case pattern.Token_ss:
			hs.onTokenSS()
		case pattern.Token_ekem:
			dst = hs.onWriteTokenEkem(dst)
		case pattern.Token_skem:
			dst = hs.onWriteTokenSkem(dst)
		case pattern.Token_psk:
			hs.onTokenPsk()
		default:
			hs.status.Err = errors.New("nyquist/HandshakeState/WriteMessage: invalid token: " + v.String())
		}

		if hs.status.Err != nil {
			return nil, hs.status.Err
		}
	}

	dst = hs.ss.EncryptAndHash(dst, payload)
	if hs.maxMessageSize > 0 && len(dst)-baseLen > hs.maxMessageSize {
		hs.status.Err = ErrMessageSize
		return nil, hs.status.Err
	}

	return hs.onDone(dst)
}

// ReadMessage processes a read step of the handshake protocol, appending the
// authentiated/decrypted message payload to dst, and returning the potentially
// new slice.
//
// Iff the handshake is complete, the error returned will be `ErrDone`.
func (hs *HandshakeState) ReadMessage(dst, payload []byte) ([]byte, error) {
	if hs.status.Err != nil {
		return nil, hs.status.Err
	}

	if hs.maxMessageSize > 0 && len(payload) > hs.maxMessageSize {
		hs.status.Err = ErrMessageSize
		return nil, hs.status.Err
	}

	if hs.isInitiator != (hs.patternIndex&1 != 0) {
		hs.status.Err = ErrOutOfOrder
		return nil, hs.status.Err
	}

	for _, v := range hs.patterns[hs.patternIndex] {
		switch v {
		case pattern.Token_e:
			payload = hs.onReadTokenE(payload)
		case pattern.Token_s:
			payload = hs.onReadTokenS(payload)
		case pattern.Token_ee:
			hs.onTokenEE()
		case pattern.Token_es:
			hs.onTokenES()
		case pattern.Token_se:
			hs.onTokenSE()
		case pattern.Token_ss:
			hs.onTokenSS()
		case pattern.Token_ekem:
			payload = hs.onReadTokenEkem(payload)
		case pattern.Token_skem:
			payload = hs.onReadTokenSkem(payload)
		case pattern.Token_psk:
			hs.onTokenPsk()
		default:
			hs.status.Err = errors.New("nyquist/HandshakeState/ReadMessage: invalid token: " + v.String())
		}

		if hs.status.Err != nil {
			return nil, hs.status.Err
		}
	}

	dst, hs.status.Err = hs.ss.DecryptAndHash(dst, payload)
	if hs.status.Err != nil {
		return nil, hs.status.Err
	}

	return hs.onDone(dst)
}

type bytesAble interface {
	encoding.BinaryMarshaler
}

func (hs *HandshakeState) handlePreMessages() error {
	preMessages := hs.cfg.Protocol.Pattern.PreMessages()
	if len(preMessages) == 0 {
		return nil
	}

	// Gather all the public keys from the config, from the initiator's
	// point of view.
	var s, e, rs, re bytesAble
	switch {
	case hs.kem != nil:
		rs, re = hs.kem.rs, hs.kem.re
		if hs.kem.s != nil {
			s = hs.kem.s.Public()
		}
		if hs.kem.e != nil {
			e = hs.kem.e.Public()
		}
	case hs.dh != nil:
		rs, re = hs.dh.rs, hs.dh.re
		if hs.dh.s != nil {
			s = hs.dh.s.Public()
		}
		if hs.dh.e != nil {
			e = hs.dh.e.Public()
		}
	default:
		panic("nyquist: no kex mechanism configured")
	}
	if !hs.isInitiator {
		s, e, rs, re = rs, re, s, e
	}

	for i, keys := range []struct {
		s, e bytesAble
		side string
	}{
		{s, e, "initiator"},
		{rs, re, "responder"},
	} {
		if i+1 > len(preMessages) {
			break
		}

		for _, v := range preMessages[i] {
			switch v {
			case pattern.Token_e:
				// While the specification allows for `e` tokens in the
				// pre-messages, there are currently no patterns that use
				// such a construct.
				//
				// While it is possible to generate `e` if it is the local
				// one that is missing, that would be stretching a use-case
				// that is already somewhat nonsensical.
				if keys.e == nil {
					return fmt.Errorf("nyquist/New: %s e not set", keys.side)
				}
				pkBytes, err := keys.e.MarshalBinary()
				if err != nil {
					return err
				}
				hs.ss.MixHash(pkBytes)
				if hs.cfg.Protocol.Pattern.NumPSKs() > 0 {
					hs.ss.MixKey(pkBytes)
				}
			case pattern.Token_s:
				if keys.s == nil {
					return fmt.Errorf("nyquist/New: %s s not set", keys.side)
				}
				blob, err := keys.s.MarshalBinary()
				if err != nil {
					return err
				}
				hs.ss.MixHash(blob)
			default:
				return errors.New("nyquist/New: invalid pre-message token: " + v.String())
			}
		}
	}

	return nil
}

// NewHandshake constructs a new HandshakeState with the provided configuration.
// This call is equivalent to the `Initialize` HandshakeState call in the
// Noise Protocol Framework specification.
func NewHandshake(cfg *HandshakeConfig) (*HandshakeState, error) {
	// TODO: Validate the config further?

	if cfg.Protocol.Pattern.NumPSKs() != len(cfg.PreSharedKeys) {
		return nil, errMissingPSK
	}
	for _, v := range cfg.PreSharedKeys {
		if len(v) != PreSharedKeySize {
			return nil, errBadPSK
		}
	}

	maxMessageSize := cfg.getMaxMessageSize()
	hs := &HandshakeState{
		cfg:            cfg,
		patterns:       cfg.Protocol.Pattern.Messages(),
		ss:             newSymmetricState(cfg.Protocol.Cipher, cfg.Protocol.Hash, maxMessageSize),
		status:         &HandshakeStatus{},
		maxMessageSize: maxMessageSize,
		isInitiator:    cfg.IsInitiator,
	}
	if cfg.Protocol.Pattern.IsKEM() {
		hs.kem = &kemState{
			impl:  cfg.Protocol.KEM,
			pkLen: cfg.Protocol.KEM.PublicKeySize(),
			ctLen: cfg.Protocol.KEM.CiphertextSize(),
		}
		hs.status.KEM = &KEMStatus{}
		var genKey seec.GenKey
		if kemCfg := cfg.KEM; kemCfg != nil {
			hs.kem.s = kemCfg.LocalStatic
			hs.kem.e = kemCfg.LocalEphemeral
			hs.kem.rs = kemCfg.RemoteStatic
			hs.kem.re = kemCfg.RemoteEphemeral
			hs.status.KEM.RemoteStatic = kemCfg.RemoteStatic
			hs.status.KEM.RemoteEphemeral = kemCfg.RemoteEphemeral

			if kemCfg.LocalEphemeral != nil {
				hs.status.KEM.LocalEphemeral = kemCfg.LocalEphemeral.Public()
			}

			genKey = kemCfg.GenKey
		}
		if genKey == nil {
			genKey = seec.GenKeyPassthrough
		}

		var err error
		hs.genRand, err = genKey(cfg.getRng(), 256)
		if err != nil {
			return nil, err
		}
	} else {
		hs.dh = &dhState{
			impl:  cfg.Protocol.DH,
			pkLen: cfg.Protocol.DH.Size(),
		}
		hs.status.DH = &DHStatus{}
		if dhCfg := cfg.DH; dhCfg != nil {
			hs.dh.s = dhCfg.LocalStatic
			hs.dh.e = dhCfg.LocalEphemeral
			hs.dh.rs = dhCfg.RemoteStatic
			hs.dh.re = dhCfg.RemoteEphemeral
			hs.status.DH.RemoteStatic = dhCfg.RemoteStatic
			hs.status.DH.RemoteEphemeral = dhCfg.RemoteEphemeral

			if dhCfg.LocalEphemeral != nil {
				hs.status.DH.LocalEphemeral = dhCfg.LocalEphemeral.Public()
			}
		}
	}

	hs.ss.InitializeSymmetric([]byte(cfg.Protocol.String()))
	hs.ss.MixHash(cfg.Prologue)
	if err := hs.handlePreMessages(); err != nil {
		return nil, err
	}

	return hs, nil
}
