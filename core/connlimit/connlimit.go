// SPDX-License-Identifier: AGPL-3.0-only

package connlimit

import (
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
)

const DefaultMaxClientConns = 1024

const DefaultMaxPeerConns = 1024

const DefaultMaxConnsPerIP = 64

const DefaultMaxLoopbackConns = DefaultMaxClientConns

type connClass int

const (
	classClient connClass = iota
	classPeer
	classLoopback
)

type pool struct {
	total int
	perIP map[string]int
}

type Limiter struct {
	mu          sync.Mutex
	maxClient   int
	maxPeer     int
	maxPerIP    int
	maxLoopback int
	client      pool
	peer        pool
	loopback    pool
}

func New(maxClient, maxPeer, maxPerIP, maxLoopback int) *Limiter {
	return &Limiter{
		maxClient:   maxClient,
		maxPeer:     maxPeer,
		maxPerIP:    maxPerIP,
		maxLoopback: maxLoopback,
	}
}

type Token struct {
	l     *Limiter
	class connClass
	key   string
}

func (t *Token) IsClient() bool {
	return t == nil || t.class == classClient
}

func classify(remoteAddr net.Addr, isPeer bool) connClass {
	if ip := AddrIP(remoteAddr); ip != nil && ip.IsLoopback() {
		return classLoopback
	}
	if isPeer {
		return classPeer
	}
	return classClient
}

func (l *Limiter) poolFor(class connClass) (*pool, int) {
	switch class {
	case classLoopback:
		return &l.loopback, l.maxLoopback
	case classPeer:
		return &l.peer, l.maxPeer
	default:
		return &l.client, l.maxClient
	}
}

func (l *Limiter) TryAcquire(remoteAddr net.Addr, isPeer bool) (*Token, bool) {
	if l == nil {
		return &Token{}, true
	}
	class := classify(remoteAddr, isPeer)
	key := perIPKey(remoteAddr)
	l.mu.Lock()
	defer l.mu.Unlock()
	p, maxTotal := l.poolFor(class)
	if maxTotal > 0 && p.total >= maxTotal {
		return nil, false
	}
	if class != classLoopback && l.maxPerIP > 0 && p.perIP[key] >= l.maxPerIP {
		return nil, false
	}
	if p.perIP == nil {
		p.perIP = make(map[string]int)
	}
	p.total++
	p.perIP[key]++
	return &Token{l: l, class: class, key: key}, true
}

func (t *Token) Release() {
	if t == nil || t.l == nil {
		return
	}
	l := t.l
	l.mu.Lock()
	defer l.mu.Unlock()
	p, _ := l.poolFor(t.class)
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

type PeerSet struct {
	ips atomic.Pointer[map[string]struct{}]
}

func NewPeerSet() *PeerSet {
	return &PeerSet{}
}

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

var lookupIP = net.LookupIP

func resolveAddr(a string) []net.IP {
	host := hostOf(a)
	if host == "" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}
	}
	if isOnion(host) {
		return nil
	}
	ips, err := lookupIP(host)
	if err != nil {
		return nil
	}
	return ips
}

func isOnion(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	return strings.HasSuffix(h, ".onion")
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
