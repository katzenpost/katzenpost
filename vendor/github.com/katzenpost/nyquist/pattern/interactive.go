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
	// NN is the NN interactive (fundemental) pattern.
	NN Pattern = &builtIn{
		name: "NN",
		messages: []Message{
			{Token_e},
			{Token_e, Token_ee},
		},
	}

	// NK is the NK interactive (fundemental) pattern.
	NK Pattern = &builtIn{
		name: "NK",
		preMessages: []Message{
			nil,
			{Token_s},
		},
		messages: []Message{
			{Token_e, Token_es},
			{Token_e, Token_ee},
		},
	}

	// NX is the NX interactive (fundemental) pattern.
	NX Pattern = &builtIn{
		name: "NX",
		messages: []Message{
			{Token_e},
			{Token_e, Token_ee, Token_s, Token_es},
		},
	}

	// XN is the XN interactive (fundemental) pattern.
	XN Pattern = &builtIn{
		name: "XN",
		messages: []Message{
			{Token_e},
			{Token_e, Token_ee},
			{Token_s, Token_se},
		},
	}

	// XK is the XK interactive (fundemental) pattern.
	XK Pattern = &builtIn{
		name: "XK",
		preMessages: []Message{
			nil,
			{Token_s},
		},
		messages: []Message{
			{Token_e, Token_es},
			{Token_e, Token_ee},
			{Token_s, Token_se},
		},
	}

	// XX is the XX interactive (fundemental) pattern.
	XX Pattern = &builtIn{
		name: "XX",
		messages: []Message{
			{Token_e},
			{Token_e, Token_ee, Token_s, Token_es},
			{Token_s, Token_se},
		},
	}

	// KN is the KN interactive (fundemental) pattern.
	KN Pattern = &builtIn{
		name: "KN",
		preMessages: []Message{
			{Token_s},
		},
		messages: []Message{
			{Token_e},
			{Token_e, Token_ee, Token_se},
		},
	}

	// KK is the KK interactive (fundemental) pattern.
	KK Pattern = &builtIn{
		name: "KK",
		preMessages: []Message{
			{Token_s},
			{Token_s},
		},
		messages: []Message{
			{Token_e, Token_es, Token_ss},
			{Token_e, Token_ee, Token_se},
		},
	}

	// KX is the KX interactive (fundemental) pattern.
	KX Pattern = &builtIn{
		name: "KX",
		preMessages: []Message{
			{Token_s},
		},
		messages: []Message{
			{Token_e},
			{Token_e, Token_ee, Token_se, Token_s, Token_es},
		},
	}

	// IN is the IN interactive (fundemental) pattern.
	IN Pattern = &builtIn{
		name: "IN",
		messages: []Message{
			{Token_e, Token_s},
			{Token_e, Token_ee, Token_se},
		},
	}

	// IK is the IK interactive (fundemental) pattern.
	IK Pattern = &builtIn{
		name: "IK",
		preMessages: []Message{
			nil,
			{Token_s},
		},
		messages: []Message{
			{Token_e, Token_es, Token_s, Token_ss},
			{Token_e, Token_ee, Token_se},
		},
	}

	// IX is the IX interactive (fundemental) pattern.
	IX Pattern = &builtIn{
		name: "IX",
		messages: []Message{
			{Token_e, Token_s},
			{Token_e, Token_ee, Token_se, Token_s, Token_es},
		},
	}

	// NNpsk0 is the NNpsk0 interactive (fundemental) pattern.
	NNpsk0 = mustMakePSK(NN, "psk0")

	// NNpsk2 is the NNpsk2 interactive (fundemental) pattern.
	NNpsk2 = mustMakePSK(NN, "psk2")

	// NKpsk0 is the NKpsk0 interactive (fundemental) pattern.
	NKpsk0 = mustMakePSK(NK, "psk0")

	// NKpsk2 is the NKpsk2 interactive (fundemental) pattern.
	NKpsk2 = mustMakePSK(NK, "psk2")

	// NXpsk2 is the NXpsk2 interactive (fundemental) pattern.
	NXpsk2 = mustMakePSK(NX, "psk2")

	// XNpsk3 is the XNpsk3 interactive (fundemental) pattern.
	XNpsk3 = mustMakePSK(XN, "psk3")

	// XKpsk3 is the XKpsk3 interactive (fundemental) pattern.
	XKpsk3 = mustMakePSK(XK, "psk3")

	// XXpsk3 is the XXpsk3 interactive (fundemental) pattern.
	XXpsk3 = mustMakePSK(XX, "psk3")

	// KNpsk0 is the KNpsk0 interactive (fundemental) pattern.
	KNpsk0 = mustMakePSK(KN, "psk0")

	// KNpsk2 is the KNpsk2 interactive (fundemental) pattern.
	KNpsk2 = mustMakePSK(KN, "psk2")

	// KKpsk0 is the KKpsk0 interactive (fundemental) pattern.
	KKpsk0 = mustMakePSK(KK, "psk0")

	// KKpsk2 is the KKpsk2 interactive (fundemental) pattern.
	KKpsk2 = mustMakePSK(KK, "psk2")

	// KXpsk2 is the KXpsk2 interactive (fundemental) pattern.
	KXpsk2 = mustMakePSK(KX, "psk2")

	// INpsk1 is the INpsk1 interactive (fundemental) pattern.
	INpsk1 = mustMakePSK(IN, "psk1")

	// INpsk2 is the INpsk2 interactive (fundemental) pattern.
	INpsk2 = mustMakePSK(IN, "psk2")

	// IKpsk1 is the IKpsk1 interactive (fundemental) pattern.
	IKpsk1 = mustMakePSK(IK, "psk1")

	// IKpsk2 is the IKpsk2 interactive (fundemental) pattern.
	IKpsk2 = mustMakePSK(IK, "psk2")

	// IXpsk2 is the IXpsk2 interactive (fundemental) pattern.
	IXpsk2 = mustMakePSK(IX, "psk2")
)
