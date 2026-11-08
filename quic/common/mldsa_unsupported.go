// SPDX-License-Identifier: AGPL-3.0-only

//go:build !go1.27

package common

import (
	"crypto"
	"errors"
)

const mldsaSupported = false

func newMLDSA65Key([]byte) (crypto.Signer, error) {
	return nil, errors.New("quic: ML-DSA-65 needs a binary built with Go 1.27 or later")
}
