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

// Package nyquist implements the Noise Protocol Framework.
package nyquist // import "github.com/katzenpost/nyquist"

import "errors"

// Version is the revision of the Noise specification implemented.
const Version = 34

var (
	// ErrNonceExhausted is the error returned when the CipherState's
	// nonce space is exhausted.
	ErrNonceExhausted = errors.New("nyquist: nonce exhausted")

	// ErrMessageSize is the error returned when an operation fails due
	// to the message size being exceeded.
	ErrMessageSize = errors.New("nyquist: oversized message")

	// ErrOpen is the error returned on a authenticated decryption failure.
	ErrOpen = errors.New("nyquist: decryption failure")

	// ErrInvalidConfig is the error returned when the configuration is invalid.
	ErrInvalidConfig = errors.New("nyquist: invalid configuration")

	// ErrOutOfOrder is the error returned when ReadMessage/WriteMessage
	// are called out of order, given the handshake's initiator status.
	ErrOutOfOrder = errors.New("nyquist: out of order handshake operation")

	// ErrDone is the error returned when the handshake is complete.
	ErrDone = errors.New("nyquist: handshake complete")

	// ErrProtocolNotSupported is the error returned when a requested protocol
	// is not supported.
	ErrProtocolNotSupported = errors.New("nyquist: protocol not supported")
)

func truncateTo32BytesMax(b []byte) []byte {
	if len(b) <= 32 {
		return b
	}

	return b[:32]
}
