// Copyright (C) 2021 Yawning Angel. All rights reserved.
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
	"errors"

	"github.com/katzenpost/nyquist/kem"
	"github.com/katzenpost/nyquist/pattern"
)

var (
	errTruncatedEkem = errors.New("nyquist/HandshakeState/ReadMessage/ekem: truncated message")
	errTruncatedSkem = errors.New("nyquist/HandshakeState/ReadMessage/skem: truncated message")

	errMissingRe = errors.New("nyquist/HandshakeState/WriteMessage/ekem: re not set")
	errMissingRs = errors.New("nyquist/HandshakeState/WriteMessage/skem: rs not set")
)

func (hs *HandshakeState) onWriteTokenE_KEM(dst []byte) []byte {
	// hs.cfg.KEM.LocalEphemeral can be used to pre-generate the ephemeral key,
	// so only generate when required.
	if hs.kem.e == nil {
		_, priv := kem.GenerateKeypair(hs.kem.impl, hs.genRand)
		hs.kem.e = priv
	}

	eBytes, err := hs.kem.e.Public().MarshalBinary()
	if err != nil {
		panic(err)
	}

	hs.status.KEM.LocalEphemeral = hs.kem.e.Public()

	hs.ss.MixHash(eBytes)
	if hs.cfg.Protocol.Pattern.NumPSKs() > 0 {
		hs.ss.MixKey(eBytes)
	}
	return append(dst, eBytes...)
}

func (hs *HandshakeState) onReadTokenE_KEM(payload []byte) []byte {
	pkLen := hs.kem.pkLen
	if len(payload) < pkLen {
		hs.status.Err = errTruncatedE
		return nil
	}
	eBytes, tail := payload[:pkLen], payload[pkLen:]
	if hs.kem.re, hs.status.Err = hs.kem.impl.UnmarshalBinaryPublicKey(eBytes); hs.status.Err != nil {
		return nil
	}
	hs.status.KEM.RemoteEphemeral = hs.kem.re
	if hs.cfg.KEM != nil && hs.cfg.KEM.Observer != nil {
		if hs.status.Err = hs.cfg.KEM.Observer.OnPeerPublicKey(pattern.Token_e, hs.kem.re); hs.status.Err != nil {
			return nil
		}
	}
	hs.ss.MixHash(eBytes)
	if hs.cfg.Protocol.Pattern.NumPSKs() > 0 {
		hs.ss.MixKey(eBytes)
	}
	return tail
}

func (hs *HandshakeState) onWriteTokenS_KEM(dst []byte) []byte {
	if hs.kem.s == nil {
		hs.status.Err = errMissingS
		return nil
	}
	sBytes, err := hs.kem.s.Public().MarshalBinary()
	if err != nil {
		panic(err)
	}
	return hs.ss.EncryptAndHash(dst, sBytes)
}

func (hs *HandshakeState) onReadTokenS_KEM(payload []byte) []byte {
	tempLen := hs.kem.pkLen
	if hs.ss.cs.HasKey() {
		// The spec says `DHLEN + 16`, but doing it this way allows this
		// implementation to support any AEAD implementation, regardless of
		// tag size.
		tempLen += hs.ss.cs.aead.Overhead()
	}
	if len(payload) < tempLen {
		hs.status.Err = errTruncatedS
		return nil
	}
	temp, tail := payload[:tempLen], payload[tempLen:]

	var sBytes []byte
	if sBytes, hs.status.Err = hs.ss.DecryptAndHash(nil, temp); hs.status.Err != nil {
		return nil
	}
	if hs.kem.rs, hs.status.Err = hs.kem.impl.UnmarshalBinaryPublicKey(sBytes); hs.status.Err != nil {
		return nil
	}
	hs.status.KEM.RemoteStatic = hs.kem.rs
	if hs.cfg.KEM != nil && hs.cfg.KEM.Observer != nil {
		if hs.status.Err = hs.cfg.KEM.Observer.OnPeerPublicKey(pattern.Token_s, hs.kem.rs); hs.status.Err != nil {
			return nil
		}
	}
	return tail
}

func (hs *HandshakeState) onReadTokenEkem(payload []byte) []byte {
	ctLen := hs.kem.ctLen
	if len(payload) < ctLen {
		hs.status.Err = errTruncatedEkem
		return nil
	}
	ctBytes, tail := payload[:ctLen], payload[ctLen:]

	hs.ss.MixHash(ctBytes)

	k, err := hs.kem.impl.Decapsulate(hs.kem.e, ctBytes)
	if err != nil {
		hs.status.Err = err
		return nil
	}

	hs.ss.MixKey(k)

	return tail
}

func (hs *HandshakeState) onWriteTokenEkem(dst []byte) []byte {
	// Invariant(?) - should have peer e
	if hs.kem.re == nil {
		// Invariant violation, missing peer e.
		hs.status.Err = errMissingRe
		return nil
	}

	// E(e):
	// 1. $ct, k_j \gets INDCPAKEM.Encap(pk;r_i)$
	ct, k, err := kem.Enc(hs.genRand, hs.kem.re)
	if err != nil {
		hs.status.Err = err
		return nil
	}
	// 2. $i \gets i +1$
	// 3. $h \gets H(h\|ct)$
	hs.ss.MixHash(ct)
	// 4. $j \gets j +1$, $n \gets 0$
	// 5. $buf \gets buf \| ct$
	hs.ss.MixKey(k) // XXX: Instead of setting k_j, this does a MixKey

	return append(dst, ct...)
}

func (hs *HandshakeState) onReadTokenSkem(payload []byte) []byte {
	tempLen := hs.kem.ctLen
	if hs.ss.cs.HasKey() {
		// The spec would say `CTLEN + 16`, but doing it this way allows this
		// implementation to support any AEAD implementation, regardless of
		// tag size.
		tempLen += hs.ss.cs.aead.Overhead()
	}
	if len(payload) < tempLen {
		hs.status.Err = errTruncatedSkem
		return nil
	}
	temp, tail := payload[:tempLen], payload[tempLen:]

	var ctBytes []byte
	if ctBytes, hs.status.Err = hs.ss.DecryptAndHash(nil, temp); hs.status.Err != nil {
		return nil
	}

	k, err := kem.Dec(hs.kem.s, ctBytes)
	if err != nil {
		hs.status.Err = err
		return nil
	}

	hs.ss.MixKeyAndHash(k)

	return tail
}

func (hs *HandshakeState) onWriteTokenSkem(dst []byte) []byte {
	// E(s):
	// 1. if $pk$ from partner available
	if hs.kem.rs == nil {
		// Invariant violation, missing peer s.
		hs.status.Err = errMissingRs
		return nil
	}

	//    1. $ct, k \gets INDCCAKEM.Encap(pk;r_i)$
	ct, k, err := kem.Enc(hs.genRand, hs.kem.rs)
	if err != nil {
		hs.status.Err = err
		return nil
	}
	//    2. $i \gets i +1$
	//    3. $ct \gets AEAD.Enc(k_j, n, h, ct)$
	//    4. $buf \gets ct$
	//    5. $n \gets n+1$
	//    6. $h \gets H(h\|ct)$
	ret := hs.ss.EncryptAndHash(dst, ct)
	//    7. $ck_j, k_j \gets KDF(ck_{j-1},k,2)$
	//    8. $j \gets j +1$, $n \gets 0$
	//    9. $buf \gets buf \| ct$
	hs.ss.MixKeyAndHash(k)

	return ret
}
