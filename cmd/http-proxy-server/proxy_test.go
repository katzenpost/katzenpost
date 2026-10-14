// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

func defaultFlag(t *testing.T, name string) string {
	t.Helper()
	return newRootCommand().Flags().Lookup(name).DefValue
}

func proxyFor(t *testing.T, host, logFile, logLevel string) (*proxy, *[]cborplugin.Command, error) {
	t.Helper()
	lb, err := log.New(logFile, logLevel, false)
	require.NoError(t, err)
	t.Cleanup(func() { lb.Close() })
	cmd := newRootCommand()
	if host != defaultFlag(t, "host") {
		require.NoError(t, cmd.Flags().Set("host", host))
	}
	hosts, err := cmd.Flags().GetStringSlice("host")
	require.NoError(t, err)
	p, err := newProxy(hosts, lb.GetLogger("http_proxy"))
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
			err = p.OnCommand(requestFor(c.url))
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
		require.Error(t, p.OnCommand(requestFor(u)))
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
	err = p.OnCommand(requestFor(srv.URL))
	for _, c := range *out {
		r := c.(*cborplugin.Response)
		require.LessOrEqualf(t, len(r.Payload), genconfigPayloadLength, "proxy read and forwarded a %d byte reply", len(r.Payload))
	}
	require.Error(t, err)
}
