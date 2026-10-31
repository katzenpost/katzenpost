// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"crypto"
	"crypto/ed25519"
	"fmt"
)

const (
	SignatureEd25519 = "Ed25519"
	SignatureMLDSA65 = "ML-DSA-65"
)

func (o *Options) signature() string {
	if o == nil || o.Signature == "" {
		return SignatureEd25519
	}
	return o.Signature
}

func validateSignature(name string) error {
	switch name {
	case "", SignatureEd25519:
	case SignatureMLDSA65:
		if !mldsaSupported {
			return fmt.Errorf("quic: Signature %q needs a binary built with Go 1.27 or later", name)
		}
	default:
		return fmt.Errorf("quic: Signature %q is not %q or %q", name, SignatureEd25519, SignatureMLDSA65)
	}
	return nil
}

// newTLSKey derives the TLS key of the given signature scheme from a 32-byte seed.
func newTLSKey(signature string, seed []byte) (crypto.Signer, error) {
	switch signature {
	case SignatureEd25519:
		return ed25519.NewKeyFromSeed(seed), nil
	case SignatureMLDSA65:
		return newMLDSA65Key(seed)
	}
	return nil, validateSignature(signature)
}

func wipeTLSKey(key crypto.Signer) {
	if key, ok := key.(ed25519.PrivateKey); ok {
		clear(key)
	}
}
