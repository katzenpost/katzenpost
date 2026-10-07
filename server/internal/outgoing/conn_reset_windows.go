// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package outgoing

import (
	"errors"
	"syscall"
)

func isConnReset(err error) bool {
	return errors.Is(err, syscall.WSAECONNRESET) || errors.Is(err, syscall.WSAECONNABORTED) || errors.Is(err, syscall.ECONNRESET)
}
