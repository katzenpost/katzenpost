// SPDX-License-Identifier: AGPL-3.0-only

package connlimit

import (
	"net"
	"strings"
	"testing"
)

func tcp(ip string) net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(ip), Port: 1}
}

func TestClientExhaustionDoesNotBlockPeer(t *testing.T) {
	l := New(2, 2, 0, 0)
	if _, ok := l.TryAcquire(tcp("1.1.1.1"), false); !ok {
		t.Fatal("first client should be admitted")
	}
	if _, ok := l.TryAcquire(tcp("1.1.1.2"), false); !ok {
		t.Fatal("second client should be admitted")
	}
	if _, ok := l.TryAcquire(tcp("1.1.1.3"), false); ok {
		t.Fatal("third client must be refused: client pool full")
	}
	if _, ok := l.TryAcquire(tcp("2.2.2.2"), true); !ok {
		t.Fatal("peer must be admitted while the client pool is exhausted")
	}
}

func TestPeerExhaustionDoesNotBlockClient(t *testing.T) {
	l := New(2, 2, 0, 0)
	if _, ok := l.TryAcquire(tcp("2.2.2.1"), true); !ok {
		t.Fatal("first peer should be admitted")
	}
	if _, ok := l.TryAcquire(tcp("2.2.2.2"), true); !ok {
		t.Fatal("second peer should be admitted")
	}
	if _, ok := l.TryAcquire(tcp("2.2.2.3"), true); ok {
		t.Fatal("third peer must be refused: peer pool full")
	}
	if _, ok := l.TryAcquire(tcp("1.1.1.1"), false); !ok {
		t.Fatal("client must be admitted while the peer pool is exhausted")
	}
}

func TestPerIPCapWithinPool(t *testing.T) {
	l := New(0, 0, 2, 0)
	if _, ok := l.TryAcquire(tcp("3.3.3.3"), false); !ok {
		t.Fatal("first from IP should be admitted")
	}
	if _, ok := l.TryAcquire(tcp("3.3.3.3"), false); !ok {
		t.Fatal("second from IP should be admitted")
	}
	if _, ok := l.TryAcquire(tcp("3.3.3.3"), false); ok {
		t.Fatal("third from same IP must be refused: per-IP cap is 2")
	}
	if _, ok := l.TryAcquire(tcp("4.4.4.4"), false); !ok {
		t.Fatal("a different IP must not be blocked by another IP's per-IP cap")
	}
}

func TestReleaseFreesExactlyOneSlot(t *testing.T) {
	l := New(1, 1, 0, 0)
	ctok, ok := l.TryAcquire(tcp("1.1.1.1"), false)
	if !ok {
		t.Fatal("client should be admitted")
	}
	if _, ok := l.TryAcquire(tcp("1.1.1.2"), false); ok {
		t.Fatal("client pool must be full")
	}
	ptok, ok := l.TryAcquire(tcp("2.2.2.2"), true)
	if !ok {
		t.Fatal("peer should be admitted")
	}

	ptok.Release()
	if _, ok := l.TryAcquire(tcp("1.1.1.2"), false); ok {
		t.Fatal("releasing a peer slot must not free a client slot")
	}

	ctok.Release()
	if _, ok := l.TryAcquire(tcp("1.1.1.2"), false); !ok {
		t.Fatal("releasing the client slot must free exactly one client slot")
	}
}

func TestReleaseBoundsPerIPMap(t *testing.T) {
	l := New(0, 0, 1, 0)
	tk, ok := l.TryAcquire(tcp("5.5.5.5"), false)
	if !ok {
		t.Fatal("should be admitted")
	}
	key := perIPKey(tcp("5.5.5.5"))
	l.mu.Lock()
	if l.client.perIP[key] != 1 {
		l.mu.Unlock()
		t.Fatal("per-IP entry should be 1 while held")
	}
	l.mu.Unlock()

	tk.Release()
	l.mu.Lock()
	if _, present := l.client.perIP[key]; present {
		l.mu.Unlock()
		t.Fatal("per-IP entry must be deleted at zero")
	}
	l.mu.Unlock()
}

func TestIPv6SlashSixtyFourKeying(t *testing.T) {
	l := New(0, 0, 1, 0)
	if _, ok := l.TryAcquire(tcp("2001:db8::1"), false); !ok {
		t.Fatal("first /64 address should be admitted")
	}
	if _, ok := l.TryAcquire(tcp("2001:db8::2"), false); ok {
		t.Fatal("second address in the same /64 must share the per-IP cap")
	}
	if _, ok := l.TryAcquire(tcp("2001:db8:0:1::1"), false); !ok {
		t.Fatal("an address in a different /64 must have an independent cap")
	}
}

func TestNilLimiterUnlimited(t *testing.T) {
	var l *Limiter
	for i := 0; i < 1000; i++ {
		tk, ok := l.TryAcquire(tcp("1.1.1.1"), false)
		if !ok {
			t.Fatalf("nil limiter must admit unconditionally at %d", i)
		}
		tk.Release()
	}
}

func TestRebuildSkipsOnionResolution(t *testing.T) {
	var looked []string
	orig := lookupIP
	lookupIP = func(host string) ([]net.IP, error) {
		looked = append(looked, host)
		return []net.IP{net.ParseIP("10.9.9.9")}, nil
	}
	defer func() { lookupIP = orig }()

	ps := NewPeerSet()
	ps.Rebuild([]string{
		"tcp://relay.example.com:1",
		"http://abcdefghij.onion:2",
		"onion123.onion.:3",
		"5.6.7.8:4",
	})

	for _, h := range looked {
		if strings.HasSuffix(strings.ToLower(strings.TrimSuffix(h, ".")), ".onion") {
			t.Fatalf("onion name %q must never be sent to the system resolver", h)
		}
	}
	if !ps.Contains(net.ParseIP("10.9.9.9")) {
		t.Fatal("a normal hostname must still be DNS-resolved into the peer set")
	}
	if !ps.Contains(net.ParseIP("5.6.7.8")) {
		t.Fatal("a literal IP peer must be in the set")
	}
}

func TestLoopbackPoolSeparateAndPerIPExempt(t *testing.T) {
	l := New(1, 1, 1, 2)
	if _, ok := l.TryAcquire(tcp("1.1.1.1"), false); !ok {
		t.Fatal("client should be admitted")
	}
	if _, ok := l.TryAcquire(tcp("1.1.1.2"), false); ok {
		t.Fatal("client pool (cap 1) must be full")
	}

	lb1, ok := l.TryAcquire(tcp("127.0.0.1"), false)
	if !ok {
		t.Fatal("loopback must be admitted from its own pool despite the client pool being full")
	}
	if _, ok := l.TryAcquire(tcp("127.0.0.1"), false); !ok {
		t.Fatal("a second loopback conn from the same IP must be admitted: loopback is per-IP exempt")
	}
	if _, ok := l.TryAcquire(tcp("127.0.0.1"), false); ok {
		t.Fatal("loopback must still be bounded by its own total cap (2)")
	}

	lb1.Release()
	if _, ok := l.TryAcquire(tcp("1.1.1.2"), false); ok {
		t.Fatal("releasing a loopback token must not free a client slot")
	}
	if _, ok := l.TryAcquire(tcp("127.0.0.1"), false); !ok {
		t.Fatal("releasing a loopback token must free exactly one loopback slot")
	}
	if _, ok := l.TryAcquire(tcp("::1"), false); ok {
		t.Fatal("::1 is loopback and shares the (now full) loopback pool")
	}
}

func TestTokenIsClient(t *testing.T) {
	l := New(0, 0, 0, 0)
	ps := NewPeerSet()
	ps.Rebuild([]string{"tcp://2.2.2.2:1"})

	client, _ := l.TryAcquire(tcp("1.1.1.1"), false)
	if !client.IsClient() {
		t.Fatal("a client-pool token must report IsClient")
	}
	peer, _ := l.TryAcquire(tcp("2.2.2.2"), true)
	if peer.IsClient() {
		t.Fatal("a peer-pool token must not report IsClient")
	}
	loop, _ := l.TryAcquire(tcp("127.0.0.1"), false)
	if loop.IsClient() {
		t.Fatal("a loopback token must not report IsClient")
	}
	var inert *Limiter
	tk, _ := inert.TryAcquire(tcp("1.1.1.1"), false)
	if !tk.IsClient() {
		t.Fatal("a nil-limiter inert token must report IsClient so connSem still bounds it")
	}
}

func TestPeerSetContains(t *testing.T) {
	var nilPS *PeerSet
	if nilPS.Contains(net.ParseIP("1.2.3.4")) {
		t.Fatal("nil PeerSet must classify nothing as a peer")
	}

	ps := NewPeerSet()
	if ps.Contains(net.ParseIP("1.2.3.4")) {
		t.Fatal("empty PeerSet must classify nothing as a peer")
	}

	ps.Rebuild([]string{"tcp://1.2.3.4:12345", "quic://[2001:db8::5]:443", "9.9.9.9:1"})
	if !ps.Contains(net.ParseIP("1.2.3.4")) {
		t.Fatal("URL-form peer address should be a peer")
	}
	if !ps.Contains(net.ParseIP("2001:db8::5")) {
		t.Fatal("IPv6 URL-form peer address should be a peer")
	}
	if !ps.Contains(net.ParseIP("9.9.9.9")) {
		t.Fatal("host:port peer address should be a peer")
	}
	if ps.Contains(net.ParseIP("8.8.8.8")) {
		t.Fatal("an address absent from the set must not be a peer")
	}
	if ps.Contains(nil) {
		t.Fatal("a nil IP is never a peer")
	}

	ps.Rebuild([]string{"tcp://7.7.7.7:1"})
	if ps.Contains(net.ParseIP("1.2.3.4")) {
		t.Fatal("a swapped-in set must not retain the previous set's peers")
	}
	if !ps.Contains(net.ParseIP("7.7.7.7")) {
		t.Fatal("the swapped-in set's peer must be present")
	}
}
