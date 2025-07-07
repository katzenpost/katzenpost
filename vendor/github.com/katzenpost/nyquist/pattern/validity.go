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

package pattern

import (
	"errors"
	"fmt"
)

// IsValid checks a pattern for validity according to the handshake pattern
// validity rules, and implementation limitations.
//
// Warning: This is not particularly fast, and should only be called when
// validating custom patterns, or testing.  KEM pattern validation is not
// fully supported yet.
func IsValid(pa Pattern) error {
	initTokens := make(map[Token]bool)
	respTokens := make(map[Token]bool)

	getSide := func(idx int) (map[Token]bool, bool, string) {
		isInitiator := idx&1 == 0
		if isInitiator {
			return initTokens, true, "initiator"
		}
		return respTokens, false, "responder"
	}

	inEither := func(t Token) bool {
		return initTokens[t] || respTokens[t]
	}

	inBoth := func(t Token) bool {
		return initTokens[t] && respTokens[t]
	}

	// Sanity-check the pre-messages.
	preMessages := pa.PreMessages()
	if len(preMessages) > 2 {
		return errors.New("nyquist/pattern: excessive pre-messages")
	}
	for i, msg := range preMessages {
		m, _, side := getSide(i)
		for _, v := range msg {
			switch v {
			case Token_e, Token_s:
				// 2. Parties must not send their static public key or ephemeral
				// public key more than once per handshake.
				if m[v] {
					return fmt.Errorf("nyquist/pattern: redundant pre-message token (%s): %s", side, v)
				}
				m[v] = true
			default:
				return fmt.Errorf("nyquist/pattern: invalid pre-message token: %s", v)
			}
		}
	}

	isKEM := pa.IsKEM()

	// Validate the messages.
	messages := pa.Messages()
	if len(messages) == 0 {
		return errors.New("nyquist/pattern: no handshake messages")
	}
	if pa.IsOneWay() && len(messages) != 1 {
		return errors.New("nyquist/pattern: excessive messages for one-way pattern")
	}
	var numDHs, numPSKs, numKEMs int
	for i, msg := range messages {
		m, isInitiator, side := getSide(i)
		for _, v := range msg {
			switch v {
			case Token_e, Token_s:
				// 2. Parties must not send their static public key or ephemeral
				// public key more than once per handshake.
				if m[v] {
					return fmt.Errorf("nyquist/pattern: redundant public key (%s): %s", side, v)
				}
			case Token_ee, Token_es, Token_se, Token_ss:
				if isKEM {
					return fmt.Errorf("nyquist/pattern: DH token in KEM pattern: %s", v)
				}

				// 3. Parties must not perform a DH calculation more than once
				// per handshake.
				if inEither(v) {
					return fmt.Errorf("nyquist/pattern: redundant DH calcuation: %s", v)
				}
				numDHs++
			case Token_ekem, Token_skem:
				if !isKEM {
					return fmt.Errorf("nyquist/pattern: KEM token in DH pattern: %s", v)
				}
				// TODO: KEM version of tracking if this is duplicated.
				numKEMs++
			case Token_psk:
				numPSKs++
			default:
				return fmt.Errorf("nyquist/pattern: invalid message token: %s", v)
			}

			// 1. Parties can only perform DH between private keys and public
			// keys they posess.
			//
			// TODO: KEM version of this rule.
			var impossibleDH Token
			switch v {
			case Token_ee:
				if !inBoth(Token_e) {
					impossibleDH = v
				}
			case Token_ss:
				if !inBoth(Token_s) {
					impossibleDH = v
				}
			case Token_es:
				if !initTokens[Token_e] || !respTokens[Token_s] {
					impossibleDH = v
				}
			case Token_se:
				if !initTokens[Token_s] || !respTokens[Token_e] {
					impossibleDH = v
				}
			default:
			}
			if impossibleDH != Token_invalid {
				return fmt.Errorf("nyquist/pattern: impossible DH: %s", v)
			}

			m[v] = true
		}

		// 4. After performing a DH between a remote public key (either static
		// or ephemeral) and the local static key, the local party must not
		// call ENCRYPT() unless it has also performed a DH between its local
		// ephemeral key and the remote public key.
		//
		// TODO: KEM version of this rule.
		var missingDH Token
		if isInitiator {
			if inEither(Token_se) && !inEither(Token_ee) {
				missingDH = Token_ee
			}
			if inEither(Token_ss) && !inEither(Token_es) {
				missingDH = Token_es
			}
		} else {
			if inEither(Token_es) && !inEither(Token_ee) {
				missingDH = Token_ee
			}
			if inEither(Token_ss) && !inEither(Token_se) {
				missingDH = Token_se
			}
		}
		if missingDH != Token_invalid {
			return fmt.Errorf("nyquist/pattern: missing DH calculation (%s): %s", side, missingDH)
		}

		if inEither(Token_psk) {
			// A party may not send any encrypted data after it processes a
			// "psk" token unless it has previously sent an epmeheral public
			// key (an "e" token), either before or after the "psk" token.
			if !m[Token_e] {
				return fmt.Errorf("nyquist/pattern: payload after pre-shared key without ephemeral (%s)", side)
			}
		}
	}

	// Patterns without any DH/KEM calculations may be "valid", but are
	// nonsensical.
	if numDHs == 0 && numKEMs == 0 {
		return errors.New("nyquist/pattern: no DH/KEM calculations at all")
	}

	// Make sure the PSK hint interface function is implemented correctly.
	if numPSKs != pa.NumPSKs() {
		return errors.New("nyquist/pattern: NumPSKs() mismatch with (pre-)messages")
	}

	return nil
}
