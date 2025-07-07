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

package pattern

var (
	// PqNN is the pqNN interactive (fundemental) pattern.
	PqNN Pattern = &builtIn{
		name: "pqNN",
		messages: []Message{
			{Token_e},
			{Token_ekem},
		},
		isKEM: true,
	}

	// PqNK is the pqNK interactive (fundemental) pattern.
	PqNK Pattern = &builtIn{
		name: "pqNK",
		preMessages: []Message{
			nil,
			{Token_s},
		},
		messages: []Message{
			{Token_skem, Token_e},
			{Token_ekem},
		},
		isKEM: true,
	}

	// PqNX is the pqNX interactive (fundemental) pattern.
	PqNX Pattern = &builtIn{
		name: "pqNX",
		messages: []Message{
			{Token_e},
			{Token_ekem, Token_s},
			{Token_skem},
		},
		isKEM: true,
	}

	// PqXN is the pqXN interactive (fundemental) pattern.
	PqXN Pattern = &builtIn{
		name: "pqXN",
		messages: []Message{
			{Token_e},
			{Token_ekem},
			{Token_s},
			{Token_skem},
		},
		isKEM: true,
	}

	// PqXK is the pqXK interactive (fundemental) pattern.
	PqXK Pattern = &builtIn{
		name: "pqXK",
		preMessages: []Message{
			nil,
			{Token_s},
		},
		messages: []Message{
			{Token_skem, Token_e},
			{Token_ekem},
			{Token_s},
			{Token_skem},
		},
		isKEM: true,
	}

	// PqXX is the pqXX interactive (fundemental) pattern.
	PqXX Pattern = &builtIn{
		name: "pqXX",
		messages: []Message{
			{Token_e},
			{Token_ekem, Token_s},
			{Token_skem, Token_s},
			{Token_skem},
		},
		isKEM: true,
	}

	// PqKN is the pqKN interactive (fundemental) pattern.
	PqKN Pattern = &builtIn{
		name: "pqKN",
		preMessages: []Message{
			{Token_s},
		},
		messages: []Message{
			{Token_e},
			{Token_ekem, Token_skem},
		},
		isKEM: true,
	}

	// PqKK is the pqKK interactive (fundemental) pattern.
	PqKK Pattern = &builtIn{
		name: "pqKK",
		preMessages: []Message{
			{Token_s},
			{Token_s},
		},
		messages: []Message{
			{Token_skem, Token_e},
			{Token_ekem, Token_skem},
		},
		isKEM: true,
	}

	// PqKX is the pqKX interactive (fundemental) pattern.
	PqKX Pattern = &builtIn{
		name: "pqKX",
		preMessages: []Message{
			{Token_s},
		},
		messages: []Message{
			{Token_e},
			{Token_ekem, Token_skem, Token_s},
			{Token_skem},
		},
		isKEM: true,
	}

	// PqIN is the pqIN interactive (fundemental) pattern.
	PqIN Pattern = &builtIn{
		name: "pqIN",
		messages: []Message{
			{Token_e, Token_s},
			{Token_ekem, Token_skem},
		},
		isKEM: true,
	}

	// PqIK is the pqIK interactive (fundemental) pattern.
	PqIK Pattern = &builtIn{
		name: "pqIK",
		preMessages: []Message{
			nil,
			{Token_s},
		},
		messages: []Message{
			{Token_skem, Token_e, Token_s},
			{Token_ekem, Token_skem},
		},
		isKEM: true,
	}

	// PqIX is the PqIX interactive (fundemental) pattern.
	PqIX Pattern = &builtIn{
		name: "pqIX",
		messages: []Message{
			{Token_e, Token_s},
			{Token_ekem, Token_skem, Token_s},
			{Token_skem},
		},
		isKEM: true,
	}
)
