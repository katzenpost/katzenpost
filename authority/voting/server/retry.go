// retry.go - Katzenpost voting authority retry logic.
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
	"math/rand"
	"net"
	"strings"
	"time"
)

func isTransientError(err error) bool {
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

func retryDelay(baseDelay, maxDelay time.Duration, jitter float64, attempt int) time.Duration {
	delay := baseDelay * time.Duration(1<<uint(attempt))
	if delay > maxDelay {
		delay = maxDelay
	}
	if jitter > 0 {
		delay += time.Duration(float64(delay) * jitter * rand.Float64())
	}
	return delay
}

func detectAddressCapabilities(addresses []string) (hasIPv4, hasIPv6 bool) {
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

func isUsableAddress(addr string, hasIPv4, hasIPv6, disableIPv4, disableIPv6 bool) bool {
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

func filterUsableAddresses(addrs []string, hasIPv4, hasIPv6, disableIPv4, disableIPv6 bool) []string {
	result := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if isUsableAddress(addr, hasIPv4, hasIPv6, disableIPv4, disableIPv6) {
			result = append(result, addr)
		}
	}
	return result
}
