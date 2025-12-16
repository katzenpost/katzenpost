// retry.go - Shared retry logic with exponential backoff.
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

// Package retry provides shared retry logic with exponential backoff
// for network operations across Katzenpost components.
package retry

import (
	"math"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/katzenpost/hpqc/rand"
)

// Default retry configuration constants
const (
	// DefaultMaxAttempts is the default maximum number of retry attempts
	DefaultMaxAttempts = 10

	// DefaultBaseDelay is the default base delay between retries
	DefaultBaseDelay = 500 * time.Millisecond

	// DefaultMaxDelay is the default maximum delay between retries
	DefaultMaxDelay = 10 * time.Second

	// DefaultJitter is the default jitter factor (0.0 to 1.0)
	DefaultJitter = 0.2
)

// Delay calculates the delay for a given retry attempt using exponential
// backoff with jitter.
func Delay(baseDelay, maxDelay time.Duration, jitter float64, attempt int) time.Duration {
	// Calculate exponential delay
	delay := float64(baseDelay) * math.Pow(2, float64(attempt))

	// Cap at maxDelay
	if delay > float64(maxDelay) {
		delay = float64(maxDelay)
	}

	if jitter > 0 {
		r := rand.NewMath()
		jitterFactor := 1 - jitter + r.Float64()*2*jitter
		delay *= jitterFactor
	}

	return time.Duration(delay)
}

// IsTransientError returns true if the error is likely transient and worth
// retrying.  This includes network timeouts, connection refused, connection
// reset, etc.
func IsTransientError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	transientPatterns := []string{
		"connection refused",
		"connection reset",
		"connection timed out",
		"timeout",
		"temporary failure",
		"no route to host",
		"network is unreachable",
		"i/o timeout",
		"eof",
		"broken pipe",
		"connection closed",
	}

	lowerErr := strings.ToLower(errStr)
	for _, pattern := range transientPatterns {
		if strings.Contains(lowerErr, pattern) {
			return true
		}
	}

	if netErr, ok := err.(net.Error); ok {
		if netErr.Timeout() {
			return true
		}
		if netErr.Temporary() {
			return true
		}
	}

	return false
}

// DetectAddressCapabilities analyzes a list of addresses (which may be URLs)
// to determine if IPv4 and/or IPv6 addresses are present.
func DetectAddressCapabilities(addresses []string) (hasIPv4, hasIPv6 bool) {
	for _, addr := range addresses {
		host := extractHostFromAddress(addr)
		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			hasIPv4 = true
		} else {
			hasIPv6 = true
		}
	}
	return
}

// FilterUsableAddresses filters addresses based on detected capabilities and
// config flags.  It returns only addresses that match the available address
// families and are not disabled.
func FilterUsableAddresses(addresses []string, hasIPv4, hasIPv6, disableIPv4, disableIPv6 bool) []string {
	var filtered []string

	for _, addr := range addresses {
		host := extractHostFromAddress(addr)
		ip := net.ParseIP(host)

		// Not an IP address (e.g.: an .onion)
		if ip == nil {
			filtered = append(filtered, addr)
			continue
		}

		isIPv4 := ip.To4() != nil

		if isIPv4 {
			if hasIPv4 && !disableIPv4 {
				filtered = append(filtered, addr)
			}
		} else {
			if hasIPv6 && !disableIPv6 {
				filtered = append(filtered, addr)
			}
		}
	}

	if len(filtered) == 0 {
		return addresses
	}
	return filtered
}

// extractHostFromAddress extracts the host portion from an address.  It
// handles URLs.
func extractHostFromAddress(addr string) string {
	// First try to parse as URL
	if u, err := url.Parse(addr); err == nil && u.Host != "" {
		host := u.Hostname()
		if host != "" {
			return host
		}
	}

	// Try to parse as host:port
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	}

	// Return as-is (plain host or IP)
	return addr
}
