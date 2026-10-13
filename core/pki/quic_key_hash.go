// SPDX-License-Identifier: AGPL-3.0-only

package pki

import "fmt"

const (
	QUICKeyHashSize      = 32
	MaxQUICKeyHashes     = 3
	maxQUICKeyHashLength = QUICKeyHashSize * MaxQUICKeyHashes
)

func IsQUICKeyHashWellFormed(h []byte) error {
	if len(h)%QUICKeyHashSize != 0 || len(h) > maxQUICKeyHashLength {
		return fmt.Errorf("QUICKeyHash is %d bytes, want 0, 32, 64 or 96", len(h))
	}
	return nil
}
