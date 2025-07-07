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

import "github.com/katzenpost/nyquist/pattern"

func (hs *HandshakeState) onWriteTokenE_DH(dst []byte) []byte {
	// hs.cfg.DH.LocalEphemeral can be used to pre-generate the ephemeral key,
	// so only generate when required.
	if hs.dh.e == nil {
		if hs.dh.e, hs.status.Err = hs.dh.impl.GenerateKeypair(hs.cfg.getRng()); hs.status.Err != nil {
			return nil
		}
	}

	eBytes := hs.dh.e.Public().Bytes()
	hs.status.DH.LocalEphemeral = hs.dh.e.Public()

	hs.ss.MixHash(eBytes)
	if hs.cfg.Protocol.Pattern.NumPSKs() > 0 {
		hs.ss.MixKey(eBytes)
	}
	return append(dst, eBytes...)
}

func (hs *HandshakeState) onReadTokenE_DH(payload []byte) []byte {
	dhLen := hs.dh.pkLen
	if len(payload) < dhLen {
		hs.status.Err = errTruncatedE
		return nil
	}
	eBytes, tail := payload[:dhLen], payload[dhLen:]
	if hs.dh.re, hs.status.Err = hs.dh.impl.ParsePublicKey(eBytes); hs.status.Err != nil {
		return nil
	}
	hs.status.DH.RemoteEphemeral = hs.dh.re
	if hs.cfg.DH != nil && hs.cfg.DH.Observer != nil {
		if hs.status.Err = hs.cfg.DH.Observer.OnPeerPublicKey(pattern.Token_e, hs.dh.re); hs.status.Err != nil {
			return nil
		}
	}
	hs.ss.MixHash(eBytes)
	if hs.cfg.Protocol.Pattern.NumPSKs() > 0 {
		hs.ss.MixKey(eBytes)
	}
	return tail
}

func (hs *HandshakeState) onWriteTokenS_DH(dst []byte) []byte {
	if hs.dh.s == nil {
		hs.status.Err = errMissingS
		return nil
	}
	sBytes := hs.dh.s.Public().Bytes()
	return hs.ss.EncryptAndHash(dst, sBytes)
}

func (hs *HandshakeState) onReadTokenS_DH(payload []byte) []byte {
	tempLen := hs.dh.pkLen
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
	if hs.dh.rs, hs.status.Err = hs.dh.impl.ParsePublicKey(sBytes); hs.status.Err != nil {
		return nil
	}
	hs.status.DH.RemoteStatic = hs.dh.rs
	if hs.cfg.DH != nil && hs.cfg.DH.Observer != nil {
		if hs.status.Err = hs.cfg.DH.Observer.OnPeerPublicKey(pattern.Token_s, hs.dh.rs); hs.status.Err != nil {
			return nil
		}
	}
	return tail
}

func (hs *HandshakeState) onTokenEE() {
	var eeBytes []byte
	if eeBytes, hs.status.Err = hs.dh.e.DH(hs.dh.re); hs.status.Err != nil {
		return
	}
	hs.ss.MixKey(eeBytes)
}

func (hs *HandshakeState) onTokenES() {
	var esBytes []byte
	if hs.isInitiator {
		esBytes, hs.status.Err = hs.dh.e.DH(hs.dh.rs)
	} else {
		esBytes, hs.status.Err = hs.dh.s.DH(hs.dh.re)
	}
	if hs.status.Err != nil {
		return
	}
	hs.ss.MixKey(esBytes)
}

func (hs *HandshakeState) onTokenSE() {
	var seBytes []byte
	if hs.isInitiator {
		seBytes, hs.status.Err = hs.dh.s.DH(hs.dh.re)
	} else {
		seBytes, hs.status.Err = hs.dh.e.DH(hs.dh.rs)
	}
	if hs.status.Err != nil {
		return
	}
	hs.ss.MixKey(seBytes)
}

func (hs *HandshakeState) onTokenSS() {
	var ssBytes []byte
	if ssBytes, hs.status.Err = hs.dh.s.DH(hs.dh.rs); hs.status.Err != nil {
		return
	}
	hs.ss.MixKey(ssBytes)
}
