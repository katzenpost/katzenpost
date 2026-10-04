// SPDX-License-Identifier: AGPL-3.0-only

package pki

import "fmt"

func IsQUICKeyHashWellFormed(h []byte) error {
	if len(h) != 0 && len(h) != 32 && len(h) != 64 {
		return fmt.Errorf("QUICKeyHash is %d bytes, want 0, 32 or 64", len(h))
	}
	return nil
}
