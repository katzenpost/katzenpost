// retry_test.go - Tests for Katzenpost voting authority retry logic.
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

package server

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
)

func TestIsTransientError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{nil, false},
		{errors.New("connection refused"), true},
		{errors.New("CONNECTION REFUSED"), true},
		{errors.New("read: connection reset by peer"), true},
		{io.EOF, true},
		{errors.New("dial tcp: i/o timeout"), true},
		{errors.New("context deadline exceeded"), true},
		{errors.New("network is unreachable"), true},
		{errors.New("no route to host"), true},
		{errors.New("broken pipe"), true},
		{errors.New("authentication failed"), false},
		{errors.New("certificate invalid"), false},
		{errors.New("VoteTooLate"), false},
		{errors.New("permission denied"), false},
	}
	for _, tt := range tests {
		got := isTransientError(tt.err)
		if got != tt.expected {
			t.Errorf("isTransientError(%v) = %v, want %v", tt.err, got, tt.expected)
		}
	}
}

func TestRetryDelay(t *testing.T) {
	tests := []struct {
		baseDelay time.Duration
		maxDelay  time.Duration
		jitter    float64
		attempt   int
		minDelay  time.Duration
		maxResult time.Duration
	}{
		{1 * time.Second, 10 * time.Second, 0, 0, 1 * time.Second, 1 * time.Second},
		{1 * time.Second, 10 * time.Second, 0, 1, 2 * time.Second, 2 * time.Second},
		{1 * time.Second, 10 * time.Second, 0, 2, 4 * time.Second, 4 * time.Second},
		{1 * time.Second, 10 * time.Second, 0, 3, 8 * time.Second, 8 * time.Second},
		{1 * time.Second, 10 * time.Second, 0, 4, 10 * time.Second, 10 * time.Second},
		{1 * time.Second, 10 * time.Second, 0, 5, 10 * time.Second, 10 * time.Second},
		{2 * time.Second, 30 * time.Second, 0, 0, 2 * time.Second, 2 * time.Second},
		{2 * time.Second, 30 * time.Second, 0, 1, 4 * time.Second, 4 * time.Second},
		{2 * time.Second, 30 * time.Second, 0, 2, 8 * time.Second, 8 * time.Second},
		{2 * time.Second, 30 * time.Second, 0, 3, 16 * time.Second, 16 * time.Second},
		{2 * time.Second, 30 * time.Second, 0, 4, 30 * time.Second, 30 * time.Second},
	}
	for _, tt := range tests {
		got := retryDelay(tt.baseDelay, tt.maxDelay, tt.jitter, tt.attempt)
		if got < tt.minDelay || got > tt.maxResult {
			t.Errorf("retryDelay(%v, %v, %v, %d) = %v, want between %v and %v",
				tt.baseDelay, tt.maxDelay, tt.jitter, tt.attempt, got, tt.minDelay, tt.maxResult)
		}
	}
}

func TestRetryDelayWithJitter(t *testing.T) {
	baseDelay := 1 * time.Second
	maxDelay := 10 * time.Second
	jitter := 0.5

	for i := 0; i < 20; i++ {
		delay := retryDelay(baseDelay, maxDelay, jitter, 0)
		if delay < baseDelay || delay > baseDelay+time.Duration(float64(baseDelay)*jitter) {
			t.Errorf("retryDelay with jitter out of range: %v", delay)
		}
	}
}

func TestDetectAddressCapabilities(t *testing.T) {
	tests := []struct {
		addresses []string
		wantIPv4  bool
		wantIPv6  bool
	}{
		{[]string{"tcp://192.168.1.1:8080"}, true, false},
		{[]string{"tcp://[2001:db8::1]:8080"}, false, true},
		{[]string{"tcp://192.168.1.1:8080", "tcp://[2001:db8::1]:8080"}, true, true},
		{[]string{"tcp://hostname:8080"}, true, false},
		{[]string{"quic://10.0.0.1:443"}, true, false},
		{[]string{"tcp://[::1]:8080"}, false, true},
		{[]string{}, false, false},
	}
	for _, tt := range tests {
		gotIPv4, gotIPv6 := detectAddressCapabilities(tt.addresses)
		if gotIPv4 != tt.wantIPv4 || gotIPv6 != tt.wantIPv6 {
			t.Errorf("detectAddressCapabilities(%v) = (%v, %v), want (%v, %v)",
				tt.addresses, gotIPv4, gotIPv6, tt.wantIPv4, tt.wantIPv6)
		}
	}
}

func TestIsUsableAddress(t *testing.T) {
	tests := []struct {
		addr        string
		hasIPv4     bool
		hasIPv6     bool
		disableIPv4 bool
		disableIPv6 bool
		expected    bool
	}{
		{"tcp://192.168.1.1:8080", true, false, false, false, true},
		{"tcp://192.168.1.1:8080", false, true, false, false, false},
		{"tcp://192.168.1.1:8080", true, false, true, false, false},
		{"tcp://[2001:db8::1]:8080", false, true, false, false, true},
		{"tcp://[2001:db8::1]:8080", true, false, false, false, false},
		{"tcp://[2001:db8::1]:8080", true, true, false, true, false},
		{"tcp://hostname:8080", false, false, false, false, true},
		{"tcp://hostname:8080", true, true, true, true, true},
		{"tcp://[fd00::1]:8080", false, true, false, false, true},
		{"tcp://[fe80::1]:8080", false, true, false, false, true},
	}
	for _, tt := range tests {
		got := isUsableAddress(tt.addr, tt.hasIPv4, tt.hasIPv6, tt.disableIPv4, tt.disableIPv6)
		if got != tt.expected {
			t.Errorf("isUsableAddress(%q, v4=%v, v6=%v, disV4=%v, disV6=%v) = %v, want %v",
				tt.addr, tt.hasIPv4, tt.hasIPv6, tt.disableIPv4, tt.disableIPv6, got, tt.expected)
		}
	}
}

func TestFilterUsableAddresses(t *testing.T) {
	addrs := []string{
		"tcp://192.168.1.1:8080",
		"tcp://[2001:db8::1]:8080",
		"tcp://10.0.0.1:443",
		"tcp://[fd00::2]:8080",
	}

	t.Run("IPv4 only", func(t *testing.T) {
		filtered := filterUsableAddresses(addrs, true, false, false, false)
		if len(filtered) != 2 {
			t.Errorf("expected 2 addresses, got %d: %v", len(filtered), filtered)
		}
	})

	t.Run("IPv6 only", func(t *testing.T) {
		filtered := filterUsableAddresses(addrs, false, true, false, false)
		if len(filtered) != 2 {
			t.Errorf("expected 2 addresses, got %d: %v", len(filtered), filtered)
		}
	})

	t.Run("dual stack", func(t *testing.T) {
		filtered := filterUsableAddresses(addrs, true, true, false, false)
		if len(filtered) != 4 {
			t.Errorf("expected 4 addresses, got %d: %v", len(filtered), filtered)
		}
	})

	t.Run("dual stack with IPv6 disabled", func(t *testing.T) {
		filtered := filterUsableAddresses(addrs, true, true, false, true)
		if len(filtered) != 2 {
			t.Errorf("expected 2 addresses, got %d: %v", len(filtered), filtered)
		}
	})

	t.Run("dual stack with IPv4 disabled", func(t *testing.T) {
		filtered := filterUsableAddresses(addrs, true, true, true, false)
		if len(filtered) != 2 {
			t.Errorf("expected 2 addresses, got %d: %v", len(filtered), filtered)
		}
	})
}

func TestDefaultRetryAttempts(t *testing.T) {
	attempts := config.DefaultRetryAttempts()
	if attempts < 5 {
		t.Errorf("DefaultRetryAttempts() = %d, want >= 5", attempts)
	}
	t.Logf("DefaultRetryAttempts() = %d", attempts)
}

func TestDefaultRetryMaxDelay(t *testing.T) {
	maxDelay := config.DefaultRetryMaxDelay()
	if maxDelay <= 0 {
		t.Errorf("DefaultRetryMaxDelay() = %v, want > 0", maxDelay)
	}
	t.Logf("DefaultRetryMaxDelay() = %v", maxDelay)
}

func TestRetryBehaviorSimulation(t *testing.T) {
	t.Run("success first attempt", func(t *testing.T) {
		attempts := 0
		err := simulateRetry(3, func() error {
			attempts++
			return nil
		})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if attempts != 1 {
			t.Errorf("expected 1 attempt, got %d", attempts)
		}
	})

	t.Run("success after retries", func(t *testing.T) {
		attempts := 0
		err := simulateRetry(5, func() error {
			attempts++
			if attempts < 3 {
				return errors.New("connection refused")
			}
			return nil
		})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if attempts != 3 {
			t.Errorf("expected 3 attempts, got %d", attempts)
		}
	})

	t.Run("permanent error no retry", func(t *testing.T) {
		attempts := 0
		err := simulateRetry(5, func() error {
			attempts++
			return errors.New("authentication failed")
		})
		if err == nil {
			t.Error("expected error")
		}
		if attempts != 1 {
			t.Errorf("expected 1 attempt for permanent error, got %d", attempts)
		}
	})

	t.Run("max retries exceeded", func(t *testing.T) {
		attempts := 0
		err := simulateRetry(3, func() error {
			attempts++
			return errors.New("connection refused")
		})
		if err == nil {
			t.Error("expected error after max retries")
		}
		if attempts != 4 {
			t.Errorf("expected 4 attempts (initial + 3 retries), got %d", attempts)
		}
	})
}

func simulateRetry(maxAttempts int, fn func() error) error {
	var lastErr error
	for attempt := 0; attempt <= maxAttempts; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}
		lastErr = err
		if !isTransientError(err) {
			return err
		}
	}
	return lastErr
}

func BenchmarkIsTransientError(b *testing.B) {
	err := errors.New("connection refused")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isTransientError(err)
	}
}

func BenchmarkRetryDelay(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		retryDelay(2*time.Second, 30*time.Second, 0.2, i%5)
	}
}

func BenchmarkFilterUsableAddresses(b *testing.B) {
	addrs := []string{
		"tcp://192.168.1.1:8080",
		"tcp://[2001:db8::1]:8080",
		"tcp://10.0.0.1:443",
		"tcp://hostname:8080",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filterUsableAddresses(addrs, true, true, false, false)
	}
}
