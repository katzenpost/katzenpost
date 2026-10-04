// SPDX-License-Identifier: AGPL-3.0-only

package retry

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

type quietTimeout struct{}

func (quietTimeout) Error() string   { return "quiet" }
func (quietTimeout) Timeout() bool   { return true }
func (quietTimeout) Temporary() bool { return false }

func TestIsTransientErrorTyped(t *testing.T) {
	require.True(t, IsTransientError(fmt.Errorf("dial: %w", context.DeadlineExceeded)))
	require.True(t, IsTransientError(fmt.Errorf("dial: %w", quietTimeout{})))
	require.True(t, IsTransientError(quietTimeout{}))
	require.True(t, IsTransientError(errors.New("connection refused")))
	require.False(t, IsTransientError(errors.New("descriptor conflict")))
	require.False(t, IsTransientError(fmt.Errorf("dial: %w", context.Canceled)))
	require.False(t, IsTransientError(nil))
}
