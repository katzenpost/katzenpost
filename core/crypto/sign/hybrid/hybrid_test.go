// hybrid_test.go - Generic hybrid signature scheme tests.
//
// Copyright (C) 2022  David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package hybrid

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/crypto/sign/dilithium"
	"github.com/katzenpost/katzenpost/core/crypto/sign/eddsa"
)

func TestHybridSignatureScheme(t *testing.T) {
	scheme := NewScheme(eddsa.Scheme, dilithium.Scheme)
	t.Logf("scheme name: %s", scheme.Name())
	t.Logf("signature size: %d", scheme.SignatureSize())
	t.Logf("public key size: %d", scheme.PublicKeySize())
	t.Logf("private key size: %d", scheme.PrivateKeySize())

	message := []byte("hello world")

	privKey, pubKey := scheme.NewKeypair()
	signature := privKey.Sign(message)
	ok := pubKey.Verify(signature, message)

	require.True(t, ok)
}

func TestTripleHybridSignatureScheme(t *testing.T) {
	scheme1 := NewScheme(eddsa.Scheme, dilithium.Scheme)
	scheme2 := eddsa.Scheme
	scheme := NewScheme(scheme1, scheme2)

	t.Logf("scheme name: %s", scheme.Name())
	t.Logf("signature size: %d", scheme.SignatureSize())
	t.Logf("public key size: %d", scheme.PublicKeySize())
	t.Logf("private key size: %d", scheme.PrivateKeySize())

	message := []byte("hello world")

	privKey, pubKey := scheme.NewKeypair()
	signature := privKey.Sign(message)
	ok := pubKey.Verify(signature, message)

	require.True(t, ok)
}
