// retry_test.go - Tests for shared retry logic.
//
// SPDX-License-Identifier: AGPL-3.0-only

package retry

import (
	"errors"
	"io"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	if DefaultMaxAttempts < 5 {
		t.Errorf("DefaultMaxAttempts = %d, want >= 5", DefaultMaxAttempts)
	}
	if DefaultBaseDelay > 2*time.Second {
		t.Errorf("DefaultBaseDelay = %v, want <= 2s", DefaultBaseDelay)
	}
	if DefaultMaxDelay > 30*time.Second {
		t.Errorf("DefaultMaxDelay = %v, want <= 30s", DefaultMaxDelay)
	}
	if DefaultJitter <= 0 || DefaultJitter > 1.0 {
		t.Errorf("DefaultJitter = %v, want 0 < j <= 1.0", DefaultJitter)
	}
}

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
		got := IsTransientError(tt.err)
		if got != tt.expected {
			t.Errorf("IsTransientError(%v) = %v, want %v", tt.err, got, tt.expected)
		}
	}
}

func TestDelay(t *testing.T) {
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
		{500 * time.Millisecond, 10 * time.Second, 0, 0, 500 * time.Millisecond, 500 * time.Millisecond},
		{500 * time.Millisecond, 10 * time.Second, 0, 1, 1 * time.Second, 1 * time.Second},
		{500 * time.Millisecond, 10 * time.Second, 0, 2, 2 * time.Second, 2 * time.Second},
		{500 * time.Millisecond, 10 * time.Second, 0, 3, 4 * time.Second, 4 * time.Second},
		{500 * time.Millisecond, 10 * time.Second, 0, 4, 8 * time.Second, 8 * time.Second},
		{500 * time.Millisecond, 10 * time.Second, 0, 5, 10 * time.Second, 10 * time.Second},
	}
	for _, tt := range tests {
		got := Delay(tt.baseDelay, tt.maxDelay, tt.jitter, tt.attempt)
		if got < tt.minDelay || got > tt.maxResult {
			t.Errorf("Delay(%v, %v, %v, %d) = %v, want between %v and %v",
				tt.baseDelay, tt.maxDelay, tt.jitter, tt.attempt, got, tt.minDelay, tt.maxResult)
		}
	}
}

func TestDelayWithJitter(t *testing.T) {
	baseDelay := 1 * time.Second
	maxDelay := 10 * time.Second
	jitter := 0.5

	for i := 0; i < 20; i++ {
		delay := Delay(baseDelay, maxDelay, jitter, 0)
		if delay < baseDelay || delay > baseDelay+time.Duration(float64(baseDelay)*jitter) {
			t.Errorf("Delay with jitter out of range: %v", delay)
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
		gotIPv4, gotIPv6 := DetectAddressCapabilities(tt.addresses)
		if gotIPv4 != tt.wantIPv4 || gotIPv6 != tt.wantIPv6 {
			t.Errorf("DetectAddressCapabilities(%v) = (%v, %v), want (%v, %v)",
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
	}
	for _, tt := range tests {
		got := IsUsableAddress(tt.addr, tt.hasIPv4, tt.hasIPv6, tt.disableIPv4, tt.disableIPv6)
		if got != tt.expected {
			t.Errorf("IsUsableAddress(%q, v4=%v, v6=%v, disV4=%v, disV6=%v) = %v, want %v",
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

	filtered := FilterUsableAddresses(addrs, true, false, false, false)
	if len(filtered) != 2 {
		t.Errorf("IPv4 only: expected 2 addresses, got %d", len(filtered))
	}

	filtered = FilterUsableAddresses(addrs, false, true, false, false)
	if len(filtered) != 2 {
		t.Errorf("IPv6 only: expected 2 addresses, got %d", len(filtered))
	}

	filtered = FilterUsableAddresses(addrs, true, true, false, false)
	if len(filtered) != 4 {
		t.Errorf("dual stack: expected 4 addresses, got %d", len(filtered))
	}
}
