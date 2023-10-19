//SPDX-FileCopyrightText: (C) 2023  David Stainton.
//SPDX-License-Identifier: AGPL-3.0-only

package bench

import (
	"testing"

	"github.com/katzenpost/katzenpost/core/crypto/sign/ed25519sphincsplus"
)

func BenchmarkSign(b *testing.B) {
	message := []byte(`
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.
`)

	privKey, pubKey := ed25519sphincsplus.Scheme.NewKeypair()
	signature := []byte{}

	for n := 0; n < b.N; n++ {
		signature = privKey.Sign(message)
	}

	if pubKey.Verify(signature, message) != true {
		panic("wtf")
	}
}

func BenchmarkVerify(b *testing.B) {
	message := []byte(`
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.
`)

	privKey, pubKey := ed25519sphincsplus.Scheme.NewKeypair()
	signature := privKey.Sign(message)

	for n := 0; n < b.N; n++ {
		if pubKey.Verify(signature, message) != true {
			panic("wtf")
		}
	}
}
