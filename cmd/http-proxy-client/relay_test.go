// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/quic/proxy/common"
)

func relay(t *testing.T, method, upstream string, sendErr error) *httptest.ResponseRecorder {
	t.Helper()
	lb, err := log.New(filepath.Join(t.TempDir(), "client.log"), "ERROR", false)
	require.NoError(t, err)
	t.Cleanup(func() { lb.Close() })
	reply, err := cbor.Marshal(&common.Response{Payload: []byte(upstream)})
	require.NoError(t, err)
	if upstream == "not cbor" {
		reply = []byte{0xff}
	}
	k := &kttp{log: lb.GetLogger("http_proxy"), send: func(context.Context, []byte) ([]byte, error) {
		if sendErr != nil {
			return nil, sendErr
		}
		return reply, nil
	}}
	rec := httptest.NewRecorder()
	k.ServeHTTP(rec, httptest.NewRequest(method, "http://example.org/", nil))
	return rec
}

func TestRelayPassesTheUpstreamStatus(t *testing.T) {
	cases := map[int]string{
		http.StatusForbidden:   "HTTP/1.1 403 Forbidden\r\nContent-Length: 22\r\n\r\nrequested host invalid",
		http.StatusNotFound:    "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found",
		http.StatusBadGateway:  "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 12\r\n\r\nfetch failed",
		http.StatusOK:          "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
		http.StatusBadRequest:  "HTTP/1.1 400 Bad Request\r\nContent-Length: 17\r\n\r\nmalformed request",
		http.StatusNoContent:   "HTTP/1.1 204 No Content\r\n\r\n",
		http.StatusNotModified: "HTTP/1.1 304 Not Modified\r\n\r\n",
	}
	for code, upstream := range cases {
		rec := relay(t, http.MethodGet, upstream, nil)
		require.Equal(t, code, rec.Code, upstream)
	}
	require.Equal(t, "requested host invalid", relay(t, http.MethodGet, cases[http.StatusForbidden], nil).Body.String())
	require.Empty(t, relay(t, http.MethodGet, cases[http.StatusNoContent], nil).Header().Values("Content-Length"))
}

func TestRelayDropsHopByHopHeaders(t *testing.T) {
	upstream := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/plain\r\nX-End-To-End: kept\r\n" +
		"Connection: close, X-Hop\r\nX-Hop: dropped\r\nKeep-Alive: timeout=5\r\n" +
		"Proxy-Connection: keep-alive\r\nProxy-Authenticate: Basic\r\nProxy-Authorization: Basic eA==\r\n" +
		"TE: trailers\r\nTrailer: X-T\r\nUpgrade: h2c\r\nContent-Length: 5\r\n\r\nhello"
	h := relay(t, http.MethodGet, upstream, nil).Header()
	require.Equal(t, "text/plain", h.Get("Content-Type"))
	require.Equal(t, "kept", h.Get("X-End-To-End"))
	for _, name := range []string{"Connection", "X-Hop", "Keep-Alive", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Upgrade", "Transfer-Encoding"} {
		require.Emptyf(t, h.Values(name), "hop-by-hop header %s forwarded", name)
	}
}

func TestRelaySetsContentLengthFromTheRelayedBody(t *testing.T) {
	rec := relay(t, http.MethodGet, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "hello", rec.Body.String())
	require.Equal(t, "5", rec.Header().Get("Content-Length"))
	require.Empty(t, rec.Header().Values("Transfer-Encoding"))
	rec = relay(t, http.MethodHead, "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "1234", rec.Header().Get("Content-Length"))
	require.Empty(t, rec.Body.String())
}

func TestRelayFailuresUseGatewayCodes(t *testing.T) {
	cases := []struct {
		name, upstream string
		sendErr        error
		want           int
	}{
		{"mixnet reply timed out", "", context.DeadlineExceeded, http.StatusGatewayTimeout},
		{"mixnet reply overdue", "", thin.ErrReplyOverdue, http.StatusGatewayTimeout},
		{"send failed", "", errors.New("no service"), http.StatusBadGateway},
		{"reply not cbor", "not cbor", nil, http.StatusBadGateway},
		{"reply not http", "garbage", nil, http.StatusBadGateway},
		{"reply body truncated", "HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort", nil, http.StatusBadGateway},
	}
	for _, c := range cases {
		require.Equal(t, c.want, relay(t, http.MethodGet, c.upstream, c.sendErr).Code, c.name)
	}
}

func TestRelayAddsNoContentType(t *testing.T) {
	lb, err := log.New(filepath.Join(t.TempDir(), "client.log"), "ERROR", false)
	require.NoError(t, err)
	t.Cleanup(func() { lb.Close() })
	reply, err := cbor.Marshal(&common.Response{Payload: []byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 22\r\n\r\nrequested host invalid")})
	require.NoError(t, err)
	srv := httptest.NewServer(&kttp{log: lb.GetLogger("http_proxy"), send: func(context.Context, []byte) ([]byte, error) { return reply, nil }})
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	require.Empty(t, resp.Header.Values("Content-Type"), "the proxy added a Content-Type the server did not send")
}
