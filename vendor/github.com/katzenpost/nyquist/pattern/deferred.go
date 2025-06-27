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
	// NK1 is the NK1 deferred pattern.
	NK1 Pattern = &builtIn{
		name: "NK1",
		preMessages: []Message{
			nil,
			{Token_s},
		},
		messages: []Message{
			{Token_e},
			{Token_e, Token_ee, Token_es},
		},
	}

	// NX1 is the NX1 deferred pattern.
	NX1 Pattern = &builtIn{
		name: "NX1",
		messages: []Message{
			{Token_e},
			{Token_e, Token_ee, Token_s},
			{Token_es},
		},
	}

	// X1N is the X1N deferred pattern.
	X1N Pattern = &builtIn{
		name: "X1N",
		messages: []Message{
			{Token_e},
			{Token_e, Token_ee},
			{Token_s},
			{Token_se},
		},
	}

	// X1K is the X1K deferred pattern.
	X1K Pattern = &builtIn{
		name: "X1K",
		preMessages: []Message{
			nil,
			{Token_s},
		},
		messages: []Message{
			{Token_e, Token_es},
			{Token_e, Token_ee},
			{Token_s},
			{Token_se},
		},
	}

	// XK1 is the XK1 deferred pattern.
	XK1 Pattern = &builtIn{
		name: "XK1",
		preMessages: []Message{
			nil,
			{Token_s},
		},
		messages: []Message{
			{Token_e},
			{Token_e, Token_ee, Token_es},
			{Token_s, Token_se},
		},
	}

	// X1K1 is the X1K1 deferred pattern.
	X1K1 Pattern = &builtIn{
		name: "X1K1",
		preMessages: []Message{
			nil,
			{Token_s},
		},
		messages: []Message{
			{Token_e},
			{Token_e, Token_ee, Token_es},
			{Token_s},
			{Token_se},
		},
	}

	// X1X is the X1X deferred pattern.
	X1X Pattern = &builtIn{
		name: "X1X",
		messages: []Message{
			{Token_e},
			{Token_e, Token_ee, Token_s, Token_es},
			{Token_s},
			{Token_se},
		},
	}

	// XX1 is the XX1 deferred pattern.
	XX1 Pattern = &builtIn{
		name: "XX1",
		messages: []Message{
			{Token_e},
			{Token_e, Token_ee, Token_s},
			{Token_es, Token_s, Token_se},
		},
	}

	// X1X1 is the X1X1 deferred pattern.
	X1X1 Pattern = &builtIn{
		name: "X1X1",
		messages: []Message{
			{Token_e},
			{Token_e, Token_ee, Token_s},
			{Token_es, Token_s},
			{Token_se},
		},
	}

	// K1N is the K1N deferred pattern.
	K1N Pattern = &builtIn{
		name: "K1N",
		preMessages: []Message{
			{Token_s},
		},
		messages: []Message{
			{Token_e},
			{Token_e, Token_ee},
			{Token_se},
		},
	}

	// K1K is the K1K deferred pattern.
	K1K Pattern = &builtIn{
		name: "K1K",
		preMessages: []Message{
			{Token_s},
			{Token_s},
		},
		messages: []Message{
			{Token_e, Token_es},
			{Token_e, Token_ee},
			{Token_se},
		},
	}

	// KK1 is the KK1 deferred pattern.
	KK1 Pattern = &builtIn{
		name: "KK1",
		preMessages: []Message{
			{Token_s},
			{Token_s},
		},
		messages: []Message{
			{Token_e},
			{Token_e, Token_ee, Token_se, Token_es},
		},
	}

	// K1K1 is the K1K1 deferred pattern.
	K1K1 Pattern = &builtIn{
		name: "K1K1",
		preMessages: []Message{
			{Token_s},
			{Token_s},
		},
		messages: []Message{
			{Token_e},
			{Token_e, Token_ee, Token_es},
			{Token_se},
		},
	}

	// K1X is the K1X deferred pattern.
	K1X Pattern = &builtIn{
		name: "K1X",
		preMessages: []Message{
			{Token_s},
		},
		messages: []Message{
			{Token_e},
			{Token_e, Token_ee, Token_s, Token_es},
			{Token_se},
		},
	}

	// KX1 is the KX1 deferred pattern.
	KX1 Pattern = &builtIn{
		name: "KX1",
		preMessages: []Message{
			{Token_s},
		},
		messages: []Message{
			{Token_e},
			{Token_e, Token_ee, Token_se, Token_s},
			{Token_es},
		},
	}

	// K1X1 is the K1X1 deferred pattern.
	K1X1 Pattern = &builtIn{
		name: "K1X1",
		preMessages: []Message{
			{Token_s},
		},
		messages: []Message{
			{Token_e},
			{Token_e, Token_ee, Token_s},
			{Token_se, Token_es},
		},
	}

	// I1N is the I1N deferred pattern.
	I1N Pattern = &builtIn{
		name: "I1N",
		messages: []Message{
			{Token_e, Token_s},
			{Token_e, Token_ee},
			{Token_se},
		},
	}

	// I1K is the I1K deferred pattern.
	I1K Pattern = &builtIn{
		name: "I1K",
		preMessages: []Message{
			nil,
			{Token_s},
		},
		messages: []Message{
			{Token_e, Token_es, Token_s},
			{Token_e, Token_ee},
			{Token_se},
		},
	}

	// IK1 is the IK1 deferred pattern.
	IK1 Pattern = &builtIn{
		name: "IK1",
		preMessages: []Message{
			nil,
			{Token_s},
		},
		messages: []Message{
			{Token_e, Token_s},
			{Token_e, Token_ee, Token_se, Token_es},
		},
	}

	// I1K1 is the I1K1 deferred pattern.
	I1K1 Pattern = &builtIn{
		name: "I1K1",
		preMessages: []Message{
			nil,
			{Token_s},
		},
		messages: []Message{
			{Token_e, Token_s},
			{Token_e, Token_ee, Token_es},
			{Token_se},
		},
	}

	// I1X is the I1X deferred pattern.
	I1X Pattern = &builtIn{
		name: "I1X",
		messages: []Message{
			{Token_e, Token_s},
			{Token_e, Token_ee, Token_s, Token_es},
			{Token_se},
		},
	}

	// IX1 is the IX1 deferred pattern.
	IX1 Pattern = &builtIn{
		name: "IX1",
		messages: []Message{
			{Token_e, Token_s},
			{Token_e, Token_ee, Token_se, Token_s},
			{Token_es},
		},
	}

	// I1X1 is the I1X1 deferred pattern.
	I1X1 Pattern = &builtIn{
		name: "I1X1",
		messages: []Message{
			{Token_e, Token_s},
			{Token_e, Token_ee, Token_s},
			{Token_se, Token_es},
		},
	}
)
