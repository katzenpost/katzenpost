// retry.go - Shared retry logic for Katzenpost.
//
// SPDX-License-Identifier: AGPL-3.0-only

package retry

import (
	"errors"
	"math/rand"
	"net"
	"strings"
	"time"
)

// Default retry configuration - single source of truth
const (
	DefaultMaxAttempts = 10
	DefaultBaseDelay   = 500 * time.Millisecond
	DefaultMaxDelay    = 10 * time.Second
	DefaultJitter      = float64(0.2)
)

// IsTransientError returns true if the error is likely transient.
func IsTransientError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, p := range []string{
		"connection refused",
		"connection reset",
		"broken pipe",
		"eof",
		"timeout",
		"deadline exceeded",
		"network is unreachable",
		"no route to host",
		"i/o timeout",
	} {
		if strings.Contains(msg, p) {
			return true
		}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return false
}

// Delay calculates exponential backoff with jitter.
func Delay(baseDelay, maxDelay time.Duration, jitter float64, attempt int) time.Duration {
	delay := baseDelay * time.Duration(1<<uint(attempt))
	if delay > maxDelay {
		delay = maxDelay
	}
	if jitter > 0 {
		delay += time.Duration(float64(delay) * jitter * rand.Float64())
	}
	return delay
}

// DetectAddressCapabilities examines addresses for IPv4/IPv6.
func DetectAddressCapabilities(addresses []string) (hasIPv4, hasIPv6 bool) {
	for _, addr := range addresses {
		host := addr
		if idx := strings.Index(addr, "://"); idx >= 0 {
			host = addr[idx+3:]
		}
		if strings.HasPrefix(host, "[") {
			hasIPv6 = true
			continue
		}
		colonIdx := strings.LastIndex(host, ":")
		if colonIdx > 0 {
			host = host[:colonIdx]
		}
		ip := net.ParseIP(host)
		if ip == nil {
			hasIPv4 = true
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

// IsUsableAddress checks if an address is usable given capabilities.
func IsUsableAddress(addr string, hasIPv4, hasIPv6, disableIPv4, disableIPv6 bool) bool {
	host := addr
	if idx := strings.Index(addr, "://"); idx >= 0 {
		host = addr[idx+3:]
	}
	if strings.HasPrefix(host, "[") {
		if end := strings.Index(host, "]"); end > 0 {
			host = host[1:end]
		}
	} else if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true
	}
	if ip.To4() != nil {
		return hasIPv4 && !disableIPv4
	}
	return hasIPv6 && !disableIPv6
}

// FilterUsableAddresses filters to usable addresses only.
func FilterUsableAddresses(addrs []string, hasIPv4, hasIPv6, disableIPv4, disableIPv6 bool) []string {
	result := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if IsUsableAddress(addr, hasIPv4, hasIPv6, disableIPv4, disableIPv6) {
			result = append(result, addr)
		}
	}
	return result
}
