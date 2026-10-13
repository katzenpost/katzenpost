// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"context"
	"crypto/x509"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestDialURLClosesTheConnectionWhenOpenStreamFails(t *testing.T) {
	ql, err := quic.ListenAddr("127.0.0.1:0", GenerateTLSConfig(), &quic.Config{MaxIncomingStreams: -1})
	require.NoError(t, err)
	defer ql.Close()
	serverConn := make(chan *quic.Conn, 1)
	go func() {
		c, err := ql.Accept(context.Background())
		if err == nil {
			serverConn <- c
		}
	}()
	u, err := url.Parse("quic://" + ql.Addr().String())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialURL(u, ctx, nil, nil)
	require.Error(t, err, "OpenStream should fail against a listener that allows no streams")
	require.Nil(t, conn)
	select {
	case sc := <-serverConn:
		select {
		case <-sc.Context().Done():
		case <-time.After(3 * time.Second):
			t.Fatalf("DialURL returned %q but left the QUIC connection open", err)
		}
	case <-time.After(3 * time.Second):
	}
}

const dialWithoutRootsChild = "KATZENPOST_QUIC_DIAL_WITHOUT_ROOTS_CHILD"

func TestDialURLDoesNotNeedSystemRoots(t *testing.T) {
	if os.Getenv(dialWithoutRootsChild) != "" {
		_, err := x509.SystemCertPool()
		require.Error(t, err, "the system roots were readable in the child")
		ql, err := quic.ListenAddr("127.0.0.1:0", GenerateTLSConfig(), Config())
		require.NoError(t, err)
		l := &QuicListener{Listener: ql}
		defer l.Close()
		u, err := url.Parse("quic://" + l.Addr().String())
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := DialURL(u, ctx, nil, nil)
		require.NoError(t, err)
		c.Close()
		return
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestDialURLDoesNotNeedSystemRoots$")
	cmd.Env = append(os.Environ(), dialWithoutRootsChild+"=1", "SSL_CERT_FILE="+dir, "SSL_CERT_DIR="+dir)
	out, err := cmd.CombinedOutput()
	lines := strings.SplitN(string(out), "\n", 4)
	require.NoError(t, err, "DialURL on a host without readable system roots:\n%s", strings.Join(lines[:min(len(lines), 3)], "\n"))
}
