// SPDX-License-Identifier: AGPL-3.0-only

package pki

import "fmt"

func IsQUICKeyHashWellFormed(h []byte) error {
	if len(h) != 0 && len(h) != 32 {
		return fmt.Errorf("QUICKeyHash is %d bytes, want 0 or 32", len(h))
	}
	return nil
}
