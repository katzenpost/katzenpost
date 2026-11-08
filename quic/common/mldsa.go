// SPDX-License-Identifier: AGPL-3.0-only

//go:build go1.27

package common

import (
	"crypto"
	"crypto/mldsa"
)

const mldsaSupported = true

func newMLDSA65Key(seed []byte) (crypto.Signer, error) {
	return mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
}
