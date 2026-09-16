// SPDX-License-Identifier: AGPL-3.0-only

// Package connlimit bounds concurrent inbound connections across two
// independent pools, client and peer, each with a per-source-IP cap.
package connlimit

import (
	"net"
	"net/url"
	"sync"
	"sync/atomic"
)

// DefaultMaxClientConns is the client-pool cap used when configuration leaves it unset.
const DefaultMaxClientConns = 1024

// DefaultMaxPeerConns is the peer-pool cap used when configuration leaves it unset.
const DefaultMaxPeerConns = 1024

// DefaultMaxConnsPerIP is the per-source-IP cap applied within each pool.
const DefaultMaxConnsPerIP = 64

type pool struct {
	total int
	perIP map[string]int
}

// Limiter admits inbound connections into a client or peer pool, each with its own total and per-IP caps.
type Limiter struct {
	mu        sync.Mutex
	maxClient int
	maxPeer   int
	maxPerIP  int
	client    pool
	peer      pool
}

// New returns a Limiter; a non-positive cap disables that limit, and a nil *Limiter is unlimited.
func New(maxClient, maxPeer, maxPerIP int) *Limiter {
	return &Limiter{maxClient: maxClient, maxPeer: maxPeer, maxPerIP: maxPerIP}
}

// Token is the slot reserved by a successful TryAcquire; Release returns exactly that slot.
type Token struct {
	l      *Limiter
	isPeer bool
	key    string
}

// TryAcquire reserves a slot in the client or peer pool without blocking, returning false when a cap is reached.
func (l *Limiter) TryAcquire(remoteAddr net.Addr, isPeer bool) (*Token, bool) {
	if l == nil {
		return &Token{}, true
	}
	key := perIPKey(remoteAddr)
	l.mu.Lock()
	defer l.mu.Unlock()
	p := &l.client
	maxTotal := l.maxClient
	if isPeer {
		p = &l.peer
		maxTotal = l.maxPeer
	}
	if maxTotal > 0 && p.total >= maxTotal {
		return nil, false
	}
	if l.maxPerIP > 0 && p.perIP[key] >= l.maxPerIP {
		return nil, false
	}
	if p.perIP == nil {
		p.perIP = make(map[string]int)
	}
	p.total++
	p.perIP[key]++
	return &Token{l: l, isPeer: isPeer, key: key}, true
}

// Release returns the slot to the same pool and per-IP entry it came from; it is safe on a nil or unlimited token.
func (t *Token) Release() {
	if t == nil || t.l == nil {
		return
	}
	l := t.l
	l.mu.Lock()
	defer l.mu.Unlock()
	p := &l.client
	if t.isPeer {
		p = &l.peer
	}
	if p.total > 0 {
		p.total--
	}
	if p.perIP != nil {
		if p.perIP[t.key]--; p.perIP[t.key] <= 0 {
			delete(p.perIP, t.key)
		}
	}
}

func perIPKey(addr net.Addr) string {
	ip := AddrIP(addr)
	if ip == nil {
		if addr == nil {
			return "addr:"
		}
		return "addr:" + addr.String()
	}
	if v4 := ip.To4(); v4 != nil {
		return string(v4)
	}
	return string(ip.Mask(net.CIDRMask(64, 128)))
}

// AddrIP extracts the source IP from a net.Addr, or nil when it carries no parseable IP.
func AddrIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case nil:
		return nil
	case *net.TCPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	return net.ParseIP(host)
}

// PeerSet is an atomically-swappable set of known peer source IPs; the empty set classifies every IP as non-peer.
type PeerSet struct {
	ips atomic.Pointer[map[string]struct{}]
}

// NewPeerSet returns an empty PeerSet.
func NewPeerSet() *PeerSet {
	return &PeerSet{}
}

// Rebuild resolves each address to its IPs and atomically replaces the set; unresolvable addresses are skipped.
func (s *PeerSet) Rebuild(addrs []string) {
	if s == nil {
		return
	}
	m := make(map[string]struct{})
	for _, a := range addrs {
		for _, ip := range resolveAddr(a) {
			m[string(ip.To16())] = struct{}{}
		}
	}
	s.ips.Store(&m)
}

// Contains reports whether ip is a known peer address; a nil PeerSet or nil ip is never a peer.
func (s *PeerSet) Contains(ip net.IP) bool {
	if s == nil || ip == nil {
		return false
	}
	m := s.ips.Load()
	if m == nil {
		return false
	}
	_, ok := (*m)[string(ip.To16())]
	return ok
}

func resolveAddr(a string) []net.IP {
	host := hostOf(a)
	if host == "" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil
	}
	return ips
}

func hostOf(a string) string {
	if u, err := url.Parse(a); err == nil && u.Host != "" {
		return u.Hostname()
	}
	if host, _, err := net.SplitHostPort(a); err == nil {
		return host
	}
	return a
}
