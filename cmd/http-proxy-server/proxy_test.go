// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
	var out []cborplugin.Command
	p := &proxy{allowedHost: map[string]struct{}{host: {}}, log: lb.GetLogger("http_proxy")}
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
