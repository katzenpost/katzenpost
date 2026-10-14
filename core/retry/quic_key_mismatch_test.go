// SPDX-License-Identifier: AGPL-3.0-only

package retry

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQUICKeyMismatchIsNeverTransient(t *testing.T) {
	for _, err := range []error{
		ErrQUICKeyMismatch,
		fmt.Errorf("connection closed: %w", ErrQUICKeyMismatch),
		fmt.Errorf("i/o timeout: %w", ErrQUICKeyMismatch),
	} {
		require.False(t, IsTransientError(err), "%v", err)
	}
}
