// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// freeAddr returns a loopback address that was bindable a moment ago.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// TestServeReportsBindConflict is the regression test for a metrics
// listener whose bind failure used to vanish inside a goroutine: an
// address already in use must be reported to the caller.
func TestServeReportsBindConflict(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer occupied.Close()

	err = Serve(occupied.Addr().String(), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot bind")
}

// Every daemon reaches the listener through MustServe, so a bind
// failure must take the component down rather than be shrugged off.
func TestMustServePanicsOnBindConflict(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer occupied.Close()

	require.Panics(t, func() { MustServe(occupied.Addr().String(), nil) })
}

func TestMustServeDoesNotPanicOnSuccess(t *testing.T) {
	require.NotPanics(t, func() { MustServe(freeAddr(t), nil) })
}

func TestServeRejectsNonLocalAddress(t *testing.T) {
	err := Serve("192.0.2.1:0", nil)
	require.Error(t, err)
}

func TestServeScrapesMetrics(t *testing.T) {
	addr := freeAddr(t)
	require.NoError(t, Serve(addr, nil))

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + addr + "/metrics")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(body), "go_goroutines")
}

// The listener must use its own mux rather than http.DefaultServeMux,
// so that a second listener does not panic on a duplicate /metrics
// registration and does not serve unrelated default-mux handlers.
func TestServeUsesDedicatedMux(t *testing.T) {
	http.HandleFunc("/unrelated", func(w http.ResponseWriter, r *http.Request) {})

	first := freeAddr(t)
	require.NoError(t, Serve(first, nil))
	second := freeAddr(t)
	require.NotPanics(t, func() {
		require.NoError(t, Serve(second, nil))
	})

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + second + "/unrelated")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}
