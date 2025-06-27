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

var (
	// N is the N one-way handshake pattern.
	N Pattern = &builtIn{
		name: "N",
		preMessages: []Message{
			nil,
			{Token_s},
		},
		messages: []Message{
			{Token_e, Token_es},
		},
		isOneWay: true,
	}

	// K is the K one-way handshake pattern.
	K Pattern = &builtIn{
		name: "K",
		preMessages: []Message{
			{Token_s},
			{Token_s},
		},
		messages: []Message{
			{Token_e, Token_es, Token_ss},
		},
		isOneWay: true,
	}

	// X is the X one-way handshake pattern.
	X Pattern = &builtIn{
		name: "X",
		preMessages: []Message{
			nil,
			{Token_s},
		},
		messages: []Message{
			{Token_e, Token_es, Token_s, Token_ss},
		},
		isOneWay: true,
	}

	// Npsk0 is the Npsk0 one-way handshake pattern.
	Npsk0 = mustMakePSK(N, "psk0")

	// Kpsk0 is the Kpsk0 one-way handshake pattern.
	Kpsk0 = mustMakePSK(K, "psk0")

	// Xpsk1 is the Xpsk1 one-way handshake pattern.
	Xpsk1 = mustMakePSK(X, "psk1")
)
