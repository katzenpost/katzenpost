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

// Package pattern implements the Noise Protocol Framework handshake pattern
// abstract interface and standard patterns.
package pattern // import "github.com/katzenpost/nyquist/pattern"

import "fmt"

var supportedPatterns = make(map[string]Pattern)

// Token is a Noise handshake pattern token.
type Token uint8

const (
	Token_invalid Token = iota
	Token_e
	Token_s

	// DH
	Token_ee
	Token_es
	Token_se
	Token_ss

	// KEM
	Token_ekem
	Token_skem

	Token_psk
)

// String returns the string representation of a Token.
func (t Token) String() string {
	switch t {
	case Token_e:
		return "e"
	case Token_s:
		return "s"
	case Token_ee:
		return "ee"
	case Token_es:
		return "es"
	case Token_se:
		return "se"
	case Token_ss:
		return "ss"
	case Token_ekem:
		return "ekem"
	case Token_skem:
		return "skem"
	case Token_psk:
		return "psk"
	default:
		return fmt.Sprintf("[invalid token: %d]", int(t))
	}
}

// Message is a sequence of pattern tokens.
type Message []Token

// Pattern is a handshake pattern.
type Pattern interface {
	fmt.Stringer

	// PreMessages returns the pre-message message patterns.
	PreMessages() []Message

	// Mesages returns the message patterns.
	Messages() []Message

	// NumPSKs returns the number of `psk` modifiers in the pattern.
	NumPSKs() int

	// IsOneWay returns true iff the pattern is one-way.
	IsOneWay() bool

	// IsKEM returns true iff the pattern uses a KEM for key exchanges.
	IsKEM() bool
}

// FromString returns a Pattern by pattern name, or nil.
func FromString(s string) Pattern {
	return supportedPatterns[s]
}

type builtIn struct {
	name        string
	preMessages []Message
	messages    []Message
	numPSKs     int
	isOneWay    bool
	isKEM       bool
}

func (pa *builtIn) String() string {
	return pa.name
}

func (pa *builtIn) PreMessages() []Message {
	return pa.preMessages
}

func (pa *builtIn) Messages() []Message {
	return pa.messages
}

func (pa *builtIn) NumPSKs() int {
	return pa.numPSKs
}

func (pa *builtIn) IsOneWay() bool {
	return pa.isOneWay
}

func (pa *builtIn) IsKEM() bool {
	return pa.isKEM
}

// Register registers a new pattern for use with `FromString()`.
func Register(pa Pattern) error {
	if err := IsValid(pa); err != nil {
		return err
	}
	supportedPatterns[pa.String()] = pa

	return nil
}

func init() {
	for _, v := range []Pattern{
		// One-way patterns.
		N,
		K,
		X,
		Npsk0,
		Kpsk0,
		Xpsk1,

		// Interactive (fundemental) patterns.
		NN,
		NK,
		NX,
		XN,
		XK,
		XX,
		KN,
		KK,
		KX,
		IN,
		IK,
		IX,
		NNpsk0,
		NNpsk2,
		NKpsk0,
		NKpsk2,
		NXpsk2,
		XNpsk3,
		XKpsk3,
		XXpsk3,
		KNpsk0,
		KNpsk2,
		KKpsk0,
		KKpsk2,
		KXpsk2,
		INpsk1,
		INpsk2,
		IKpsk1,
		IKpsk2,
		IXpsk2,

		// Deferred patterns.
		NK1,
		NX1,
		X1N,
		X1K,
		XK1,
		X1K1,
		X1X,
		XX1,
		X1X1,
		K1N,
		K1K,
		KK1,
		K1K1,
		K1X,
		KX1,
		K1X1,
		I1N,
		I1K,
		IK1,
		I1K1,
		I1X,
		IX1,
		I1X1,

		// Post Quantum One-way KEM patterns.
		PqN,

		// Post Quantum Interactive (fundemental) KEM patterns.
		PqNN,
		PqNK,
		PqNX,
		PqXN,
		PqXK,
		PqXX,
		PqKN,
		PqKK,
		PqKX,
		PqIN,
		PqIK,
		PqIX,
		// TODO: PSK patterns?
	} {
		if err := Register(v); err != nil {
			panic("nyquist/pattern: failed to register built-in pattern: " + err.Error())
		}
	}
}
