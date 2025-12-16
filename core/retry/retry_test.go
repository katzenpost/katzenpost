// retry_test.go - Tests for shared retry logic.
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

package retry

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDelay(t *testing.T) {
	require := require.New(t)

	baseDelay := 100 * time.Millisecond
	maxDelay := 1 * time.Second

	t.Run("exponential growth", func(t *testing.T) {
		d0 := Delay(baseDelay, maxDelay, 0, 0)
		require.Equal(100*time.Millisecond, d0)

		d1 := Delay(baseDelay, maxDelay, 0, 1)
		require.Equal(200*time.Millisecond, d1)

		d2 := Delay(baseDelay, maxDelay, 0, 2)
		require.Equal(400*time.Millisecond, d2)

		d3 := Delay(baseDelay, maxDelay, 0, 3)
		require.Equal(800*time.Millisecond, d3)
	})

	t.Run("max delay cap", func(t *testing.T) {
		d10 := Delay(baseDelay, maxDelay, 0, 10)
		require.Equal(maxDelay, d10)
	})

	t.Run("jitter range", func(t *testing.T) {
		jitter := 0.2
		for i := 0; i < 100; i++ {
			d := Delay(baseDelay, maxDelay, jitter, 0)
			require.GreaterOrEqual(d, 80*time.Millisecond)
			require.LessOrEqual(d, 120*time.Millisecond)
		}
	})
}

func TestIsTransientError(t *testing.T) {
	require := require.New(t)

	t.Run("nil error", func(t *testing.T) {
		require.False(IsTransientError(nil))
	})

	t.Run("connection refused", func(t *testing.T) {
		err := errors.New("dial tcp 127.0.0.1:8080: connect: connection refused")
		require.True(IsTransientError(err))
	})

	t.Run("connection reset", func(t *testing.T) {
		err := errors.New("read: connection reset by peer")
		require.True(IsTransientError(err))
	})

	t.Run("timeout", func(t *testing.T) {
		err := errors.New("i/o timeout")
		require.True(IsTransientError(err))
	})

	t.Run("EOF", func(t *testing.T) {
		err := errors.New("unexpected EOF")
		require.True(IsTransientError(err))
	})

	t.Run("permanent error", func(t *testing.T) {
		err := errors.New("invalid certificate")
		require.False(IsTransientError(err))
	})

	t.Run("authentication error", func(t *testing.T) {
		err := errors.New("authentication failed")
		require.False(IsTransientError(err))
	})
}

// mockNetError implements net.Error for testing
type mockNetError struct {
	timeout   bool
	temporary bool
	msg       string
}

func (e *mockNetError) Error() string   { return e.msg }
func (e *mockNetError) Timeout() bool   { return e.timeout }
func (e *mockNetError) Temporary() bool { return e.temporary }

func TestIsTransientError_NetError(t *testing.T) {
	require := require.New(t)

	t.Run("timeout net error", func(t *testing.T) {
		err := &mockNetError{timeout: true, msg: "operation timed out"}
		require.True(IsTransientError(err))
	})

	t.Run("temporary net error", func(t *testing.T) {
		err := &mockNetError{temporary: true, msg: "temporary failure"}
		require.True(IsTransientError(err))
	})

	t.Run("permanent net error", func(t *testing.T) {
		err := &mockNetError{timeout: false, temporary: false, msg: "permanent failure"}
		require.False(IsTransientError(err))
	})
}

func TestDetectAddressCapabilities(t *testing.T) {
	require := require.New(t)

	t.Run("IPv4 only", func(t *testing.T) {
		addrs := []string{"tcp://127.0.0.1:8080", "tcp://192.168.1.1:9000"}
		hasIPv4, hasIPv6 := DetectAddressCapabilities(addrs)
		require.True(hasIPv4)
		require.False(hasIPv6)
	})

	t.Run("IPv6 only", func(t *testing.T) {
		addrs := []string{"tcp://[::1]:8080", "tcp://[fe80::1]:9000"}
		hasIPv4, hasIPv6 := DetectAddressCapabilities(addrs)
		require.False(hasIPv4)
		require.True(hasIPv6)
	})

	t.Run("dual stack", func(t *testing.T) {
		addrs := []string{"tcp://127.0.0.1:8080", "tcp://[::1]:8080"}
		hasIPv4, hasIPv6 := DetectAddressCapabilities(addrs)
		require.True(hasIPv4)
		require.True(hasIPv6)
	})

	t.Run("empty addresses", func(t *testing.T) {
		hasIPv4, hasIPv6 := DetectAddressCapabilities(nil)
		require.False(hasIPv4)
		require.False(hasIPv6)
	})

	t.Run("hostnames only", func(t *testing.T) {
		addrs := []string{"tcp://localhost:8080", "tcp://example.com:9000"}
		hasIPv4, hasIPv6 := DetectAddressCapabilities(addrs)
		require.False(hasIPv4)
		require.False(hasIPv6)
	})
}

func TestFilterUsableAddresses(t *testing.T) {
	require := require.New(t)

	t.Run("IPv4 host filters to IPv4 peers", func(t *testing.T) {
		addrs := []string{
			"tcp://127.0.0.1:8080",
			"tcp://192.168.1.1:8080",
			"tcp://[::1]:8080",
			"tcp://[fe80::1]:8080",
		}
		// Host has IPv4 only
		filtered := FilterUsableAddresses(addrs, true, false, false, false)
		require.Len(filtered, 2)
		require.Contains(filtered, "tcp://127.0.0.1:8080")
		require.Contains(filtered, "tcp://192.168.1.1:8080")
	})

	t.Run("IPv6 host filters to IPv6 peers", func(t *testing.T) {
		addrs := []string{
			"tcp://127.0.0.1:8080",
			"tcp://192.168.1.1:8080",
			"tcp://[::1]:8080",
			"tcp://[fe80::1]:8080",
		}
		// Host has IPv6 only
		filtered := FilterUsableAddresses(addrs, false, true, false, false)
		require.Len(filtered, 2)
		require.Contains(filtered, "tcp://[::1]:8080")
		require.Contains(filtered, "tcp://[fe80::1]:8080")
	})

	t.Run("dual stack host returns all", func(t *testing.T) {
		addrs := []string{
			"tcp://127.0.0.1:8080",
			"tcp://[::1]:8080",
		}
		filtered := FilterUsableAddresses(addrs, true, true, false, false)
		require.Len(filtered, 2)
	})

	t.Run("disable IPv4 filters out IPv4", func(t *testing.T) {
		addrs := []string{
			"tcp://127.0.0.1:8080",
			"tcp://[::1]:8080",
		}
		// Host has both, but IPv4 disabled
		filtered := FilterUsableAddresses(addrs, true, true, true, false)
		require.Len(filtered, 1)
		require.Contains(filtered, "tcp://[::1]:8080")
	})

	t.Run("disable IPv6 filters out IPv6", func(t *testing.T) {
		addrs := []string{
			"tcp://127.0.0.1:8080",
			"tcp://[::1]:8080",
		}
		// Host has both, but IPv6 disabled
		filtered := FilterUsableAddresses(addrs, true, true, false, true)
		require.Len(filtered, 1)
		require.Contains(filtered, "tcp://127.0.0.1:8080")
	})

	t.Run("hostnames pass through with capability", func(t *testing.T) {
		addrs := []string{
			"tcp://localhost:8080",
			"tcp://example.com:8080",
			"tcp://127.0.0.1:8080",
		}
		filtered := FilterUsableAddresses(addrs, true, false, false, false)
		require.Len(filtered, 3)
	})

	t.Run("empty result returns original", func(t *testing.T) {
		addrs := []string{"tcp://[::1]:8080"}
		// Host has IPv4 only, peer has IPv6 only
		filtered := FilterUsableAddresses(addrs, true, false, false, false)
		// Should return original since filtering would leave empty
		require.Equal(addrs, filtered)
	})

	t.Run("all disabled returns original", func(t *testing.T) {
		addrs := []string{"tcp://127.0.0.1:8080", "tcp://[::1]:8080"}
		filtered := FilterUsableAddresses(addrs, true, true, true, true)
		require.Equal(addrs, filtered)
	})
}

func TestExtractHostFromAddress(t *testing.T) {
	require := require.New(t)

	require.Equal("127.0.0.1", extractHostFromAddress("tcp://127.0.0.1:8080"))
	require.Equal("127.0.0.1", extractHostFromAddress("quic://127.0.0.1:8080"))
	require.Equal("::1", extractHostFromAddress("tcp://[::1]:8080"))
	require.Equal("fe80::1", extractHostFromAddress("tcp://[fe80::1]:8080"))
	require.Equal("localhost", extractHostFromAddress("tcp://localhost:8080"))
	require.Equal("example.com", extractHostFromAddress("tcp://example.com:8080"))

	require.Equal("127.0.0.1", extractHostFromAddress("127.0.0.1:8080"))
	require.Equal("::1", extractHostFromAddress("[::1]:8080"))
	require.Equal("localhost", extractHostFromAddress("localhost:8080"))

	require.Equal("127.0.0.1", extractHostFromAddress("127.0.0.1"))
	require.Equal("example.com", extractHostFromAddress("example.com"))
}

func TestDefaultConstants(t *testing.T) {
	require := require.New(t)

	require.Equal(10, DefaultMaxAttempts)
	require.Equal(500*time.Millisecond, DefaultBaseDelay)
	require.Equal(10*time.Second, DefaultMaxDelay)
	require.Equal(0.2, DefaultJitter)
}

var _ net.Error = (*mockNetError)(nil)
