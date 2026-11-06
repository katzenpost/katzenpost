// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"sync"
	"time"
)

// A registration with a voucher router and an advertisement in a service
// directory are leases: the request names an expiry, in Unix seconds, and
// the plugin forgets the record once it passes. A request's expiry must
// lie after the plugin's clock and at most the plugin's longest lease plus
// MaxClockSkew ahead of it, so a request is only ever valid within its own
// window and a replay of it after that window is refused for being out of
// date.

// MaxClockSkew is how far ahead of the plugin's clock a lease may reach
// beyond the longest lease, allowing for the clocks of the two to differ.
const MaxClockSkew = 10 * time.Minute

var (
	seqMu   sync.Mutex
	lastSeq uint64
)

// NextSeq returns a sequence number for a request that replaces an earlier
// one: the time in nanoseconds, and always more than the last returned.
func NextSeq() uint64 {
	seqMu.Lock()
	defer seqMu.Unlock()
	lastSeq = max(lastSeq+1, uint64(time.Now().UnixNano()))
	return lastSeq
}

// LeaseExpiry is the expiry a client asks for to hold a lease as long as
// a plugin grants: max from now.
func LeaseExpiry(max time.Duration) uint64 {
	return uint64(time.Now().Add(max).Unix())
}

// CheckLease validates a requested expiry against a plugin's clock and
// its longest lease. It returns when the plugin may forget every record of
// the request's sender that this request could have replaced: after that
// no request made before now is still in date.
func CheckLease(now time.Time, expiry uint64, longest time.Duration) (keep uint64, ok bool) {
	keep = uint64(now.Add(longest + MaxClockSkew).Unix())
	return keep, expiry > uint64(now.Unix()) && expiry <= keep
}
