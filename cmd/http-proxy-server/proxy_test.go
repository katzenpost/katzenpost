// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/quic/proxy/common"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

func defaultFlag(t *testing.T, name string) string {
	t.Helper()
	return newRootCommand().Flags().Lookup(name).DefValue
}

func proxyFor(t *testing.T, host, logFile, logLevel string) (*proxy, *[]cborplugin.Command, error) {
	t.Helper()
	t.Setenv(cborplugin.PluginPayloadLengthEnv, strconv.Itoa(genconfigPayloadLength))
	lb, err := log.New(logFile, logLevel, false)
	require.NoError(t, err)
	t.Cleanup(func() { lb.Close() })
	cmd := newRootCommand()
	if host != defaultFlag(t, "host") {
		require.NoError(t, cmd.Flags().Set("host", host))
	}
	hosts, err := cmd.Flags().GetStringSlice("host")
	require.NoError(t, err)
	payloadLength, err := cmd.Flags().GetInt("payload_length")
	require.NoError(t, err)
	p, err := newProxy(hosts, payloadLength, lb.GetLogger("http_proxy"))
	if err != nil {
		return nil, nil, err
	}
	var out []cborplugin.Command
	p.write = func(c cborplugin.Command) { out = append(out, c) }
	return p, &out, nil
}

func requestFor(url string) *cborplugin.Request {
	host := strings.TrimPrefix(url, "http://")
	return &cborplugin.Request{ID: 1, Payload: []byte(fmt.Sprintf("GET %s/ HTTP/1.1\r\nHost: %s\r\n\r\n", url, host))}
}

func TestProxyRefusesServiceNodeLoopback(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "internal")
	}))
	defer srv.Close()
	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	cases := []struct{ name, host, url string }{
		{"default host", defaultFlag(t, "host"), srv.URL},
		{"wildcard", "*", srv.URL},
		{"name resolving to loopback", "localhost:" + port, "http://localhost:" + port},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hits.Store(0)
			p, out, err := proxyFor(t, c.host, filepath.Join(t.TempDir(), "proxy.log"), "ERROR")
			if err != nil {
				return
			}
			err = p.serve(requestFor(c.url))
			require.Zerof(t, hits.Load(), "proxy with --host %q fetched %s from the service node's loopback (err=%v, replies=%d)", c.host, c.url, err, len(*out))
		})
	}
}

func TestProxyRequiresHost(t *testing.T) {
	_, _, err := proxyFor(t, defaultFlag(t, "host"), filepath.Join(t.TempDir(), "proxy.log"), "ERROR")
	require.Error(t, err)
}

func TestIsGlobalAddress(t *testing.T) {
	refused := []string{
		"127.0.0.1", "127.255.255.254", "::1", "::ffff:127.0.0.1", "::ffff:10.1.2.3",
		"10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1",
		"169.254.169.254", "fe80::1", "fc00::1", "fd12:3456::1",
		"0.0.0.0", "0.1.2.3", "::", "224.0.0.1", "239.255.255.250", "ff02::1", "ff0e::1",
		"100.64.0.1", "192.0.0.8", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1",
		"240.0.0.1", "255.255.255.255", "::7f00:1", "64:ff9b::7f00:1", "64:ff9b:1::1",
		"100::1", "2001::1", "2001:db8::1", "2002:7f00:1::1", "fec0::1",
	}
	for _, s := range refused {
		require.Falsef(t, isGlobalAddress(netip.MustParseAddr(s)), "%s treated as global", s)
		require.ErrorIsf(t, refuseNonGlobal("tcp", netip.AddrPortFrom(netip.MustParseAddr(s), 80).String(), nil), errNonGlobalAddress, "%s dialable", s)
	}
	allowed := []string{"1.1.1.1", "8.8.8.8", "::ffff:8.8.8.8", "2606:4700:4700::1111", "2a00:1450:4001::1"}
	for _, s := range allowed {
		require.Truef(t, isGlobalAddress(netip.MustParseAddr(s)), "%s treated as non-global", s)
		require.NoErrorf(t, refuseNonGlobal("tcp", netip.AddrPortFrom(netip.MustParseAddr(s), 443).String(), nil), "%s refused", s)
	}
	require.ErrorIs(t, refuseNonGlobal("tcp", "not-an-address", nil), errNonGlobalAddress)
}

func TestProxyRefusesIPv6Loopback(t *testing.T) {
	l, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback")
	}
	var hits atomic.Int32
	srv := &httptest.Server{Listener: l, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) })}}
	srv.Start()
	defer srv.Close()
	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	for _, u := range []string{srv.URL, "http://[::ffff:127.0.0.1]:" + port} {
		p, _, err := proxyFor(t, "*", filepath.Join(t.TempDir(), "proxy.log"), "ERROR")
		require.NoError(t, err)
		require.Error(t, p.serve(requestFor(u)))
	}
	require.Zero(t, hits.Load())
}

const genconfigPayloadLength = 2000

func dialAnything(p *proxy) {
	p.client.Transport.(*http.Transport).DialContext = (&net.Dialer{}).DialContext
}

func TestProxyCapsReplyBeforeReading(t *testing.T) {
	const body = 64 << 20
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := make([]byte, 1<<20)
		for i := 0; i < body>>20; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	p, out, err := proxyFor(t, "*", filepath.Join(t.TempDir(), "proxy.log"), "ERROR")
	require.NoError(t, err)
	dialAnything(p)
	err = p.serve(requestFor(srv.URL))
	for _, c := range *out {
		r := c.(*cborplugin.Response)
		require.LessOrEqualf(t, len(r.Payload), genconfigPayloadLength, "proxy read and forwarded a %d byte reply", len(r.Payload))
	}
	require.Error(t, err)
}

func TestProxyRepliesWithinPayloadLength(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "small")
	}))
	defer srv.Close()
	p, out, err := proxyFor(t, "*", filepath.Join(t.TempDir(), "proxy.log"), "ERROR")
	require.NoError(t, err)
	dialAnything(p)
	require.NoError(t, p.serve(requestFor(srv.URL)))
	require.Len(t, *out, 1)
	r := (*out)[0].(*cborplugin.Response)
	require.LessOrEqual(t, len(r.Payload), p.payloadLength)
	require.Contains(t, string(r.Payload), "small")
}

func TestProxyRefusesReplyThatGrowsPastPayloadLength(t *testing.T) {
	cases := map[string]int{"body at the limit": genconfigPayloadLength, "headers past the limit": 0}
	for name, n := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if n == 0 {
					w.Header().Set("X-Pad", strings.Repeat("a", 2*genconfigPayloadLength))
				}
				w.Write(make([]byte, n))
			}))
			defer srv.Close()
			p, out, err := proxyFor(t, "*", filepath.Join(t.TempDir(), "proxy.log"), "ERROR")
			require.NoError(t, err)
			dialAnything(p)
			require.Error(t, p.serve(requestFor(srv.URL)))
			require.Equal(t, http.StatusBadGateway, refusalStatus(t, p, *out))
		})
	}
}

func TestProxyFetchHasDeadline(t *testing.T) {
	p, _, err := proxyFor(t, "*", filepath.Join(t.TempDir(), "proxy.log"), "ERROR")
	require.NoError(t, err)
	require.Positive(t, p.client.Timeout)
	require.Positive(t, p.client.Transport.(*http.Transport).ResponseHeaderTimeout)
}

func TestProxyLogKeepsNoRequestContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	levels := map[string]string{"default level": defaultFlag(t, "log_level"), "DEBUG": "DEBUG"}
	for name, level := range levels {
		for _, reachable := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s reachable=%v", name, reachable), func(t *testing.T) {
				f := filepath.Join(t.TempDir(), "proxy.log")
				p, _, err := proxyFor(t, "*", f, level)
				require.NoError(t, err)
				if reachable {
					dialAnything(p)
				}
				req := &cborplugin.Request{ID: 1, Payload: []byte("GET " + srv.URL + "/secret-page HTTP/1.1\r\nHost: x\r\nCookie: sid=s3cr3t\r\n\r\n")}
				err = p.serve(req)
				b, rerr := os.ReadFile(f)
				require.NoError(t, rerr)
				for _, secret := range []string{"secret-page", "s3cr3t", srv.URL[len("http://"):]} {
					require.NotContainsf(t, string(b), secret, "log at %s:\n%s", level, string(b))
					if err != nil {
						require.NotContainsf(t, err.Error(), secret, "returned error is logged by the plugin server")
					}
				}
			})
		}
	}
}

func TestProxyTakesThePayloadLengthFromTheHost(t *testing.T) {
	cases := []struct {
		host, flag string
		want       int
	}{
		{"1000", "", 1000},
		{"1000", "500", 500},
		{"1000", "3000", 1000},
		{"", "500", 500},
		{"", "", 0},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("host=%q flag=%q", c.host, c.flag), func(t *testing.T) {
			t.Setenv(cborplugin.PluginPayloadLengthEnv, c.host)
			cmd := newRootCommand()
			if c.flag != "" {
				require.NoError(t, cmd.Flags().Set("payload_length", c.flag))
			}
			n, err := cmd.Flags().GetInt("payload_length")
			require.NoError(t, err)
			lb, err := log.New(filepath.Join(t.TempDir(), "proxy.log"), "ERROR", false)
			require.NoError(t, err)
			t.Cleanup(func() { lb.Close() })
			p, err := newProxy([]string{"*"}, n, lb.GetLogger("http_proxy"))
			if c.want == 0 {
				require.Error(t, err, "no payload length from the host or the flag")
				return
			}
			require.NoError(t, err)
			require.Equal(t, c.want, p.payloadLength)
			require.Equal(t, int64(c.want), p.client.Transport.(*http.Transport).MaxResponseHeaderBytes)
		})
	}
	t.Setenv(cborplugin.PluginPayloadLengthEnv, "bogus")
	lb, err := log.New(filepath.Join(t.TempDir(), "proxy.log"), "ERROR", false)
	require.NoError(t, err)
	t.Cleanup(func() { lb.Close() })
	_, err = newProxy([]string{"*"}, 500, lb.GetLogger("http_proxy"))
	require.Error(t, err, "bad host payload length accepted")
}

func refusalStatus(t *testing.T, p *proxy, out []cborplugin.Command) int {
	t.Helper()
	require.Len(t, out, 1, "no reply to a refused request")
	r := out[0].(*cborplugin.Response)
	require.Equal(t, uint64(1), r.ID)
	require.LessOrEqual(t, len(r.Payload), p.payloadLength)
	var cr common.Response
	_, err := cbor.UnmarshalFirst(r.Payload, &cr)
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(cr.Payload)), nil)
	require.NoError(t, err)
	return resp.StatusCode
}

func TestProxyAnswersARefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	cases := []struct {
		name, host string
		payload    string
		want       int
	}{
		{"malformed", "*", "not http", http.StatusBadRequest},
		{"not absolute", "*", "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n", http.StatusBadRequest},
		{"host not allowed", "example.org:1", string(requestFor(srv.URL).Payload), http.StatusForbidden},
		{"fetch failed", "*", string(requestFor(srv.URL).Payload), http.StatusBadGateway},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, out, err := proxyFor(t, c.host, filepath.Join(t.TempDir(), "proxy.log"), "ERROR")
			require.NoError(t, err)
			require.Error(t, p.serve(&cborplugin.Request{ID: 1, SURB: []byte("surb"), Payload: []byte(c.payload)}))
			require.Equal(t, c.want, refusalStatus(t, p, *out))
			require.Equal(t, []byte("surb"), (*out)[0].(*cborplugin.Response).SURB)
		})
	}
}

func TestProxySendsNoRefusalLargerThanTheBound(t *testing.T) {
	lb, err := log.New(filepath.Join(t.TempDir(), "proxy.log"), "ERROR", false)
	require.NoError(t, err)
	t.Cleanup(func() { lb.Close() })
	p, err := newProxy([]string{"*"}, 10, lb.GetLogger("http_proxy"))
	require.NoError(t, err)
	var out []cborplugin.Command
	p.write = func(c cborplugin.Command) { out = append(out, c) }
	require.Error(t, p.serve(&cborplugin.Request{ID: 1, Payload: []byte("not http")}))
	require.Empty(t, out)
}

func TestProxyFetchesConcurrentlyUpToItsBound(t *testing.T) {
	const bound, extra = 8, 3
	var inFlight, peak atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		<-release
	}))
	defer srv.Close()
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	defer free()
	p, _, err := proxyFor(t, "*", filepath.Join(t.TempDir(), "proxy.log"), "ERROR")
	require.NoError(t, err)
	dialAnything(p)
	var mu sync.Mutex
	replies := 0
	p.write = func(cborplugin.Command) {
		mu.Lock()
		defer mu.Unlock()
		replies++
	}
	go func() {
		for i := 0; i < bound+extra; i++ {
			p.OnCommand(requestFor(srv.URL))
		}
	}()
	require.Eventually(t, func() bool { return peak.Load() == bound }, 10*time.Second, 10*time.Millisecond, "slow fetches did not run side by side up to the bound")
	time.Sleep(100 * time.Millisecond)
	require.EqualValues(t, bound, inFlight.Load(), "more fetches in flight than the bound")
	free()
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return replies == bound+extra
	}, 10*time.Second, 10*time.Millisecond)
	require.EqualValues(t, bound, peak.Load())
}
