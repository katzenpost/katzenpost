// SPDX-License-Identifier: AGPL-3.0-only

package outgoing

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
)

type refusedGlue struct {
	glue.Glue
	cfg     *config.Config
	backend *log.Backend
	idPub   sign.PublicKey
	link    kem.PrivateKey
}

func (g *refusedGlue) Config() *config.Config            { return g.cfg }
func (g *refusedGlue) LogBackend() *log.Backend          { return g.backend }
func (g *refusedGlue) IdentityPublicKey() sign.PublicKey { return g.idPub }
func (g *refusedGlue) LinkKey() kem.PrivateKey           { return g.link }

func handshakeLog(t *testing.T, serve func(net.Conn)) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		serve(c)
	}()

	logPath := filepath.Join(t.TempDir(), "log")
	backend, err := log.New(logPath, "DEBUG", false)
	require.NoError(t, err)
	idPub, _, err := benchSignScheme.GenerateKey()
	require.NoError(t, err)
	_, link, err := benchKEMScheme.GenerateKeyPair()
	require.NoError(t, err)
	cfg := &config.Config{Debug: &config.Debug{HandshakeTimeout: 2000}}
	co := &connector{glue: &refusedGlue{cfg: cfg, backend: backend, idPub: idPub, link: link}}
	peerPub, _, err := benchSignScheme.GenerateKey()
	require.NoError(t, err)
	peerID, err := peerPub.MarshalBinary()
	require.NoError(t, err)
	c := newOutgoingConn(co, &cpki.MixDescriptor{Name: "peer", IdentityKey: peerID}, benchGeometry, benchKEMScheme)

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	c.onConnEstablished(conn, make(chan struct{}))
	require.NoError(t, backend.Close())
	b, err := os.ReadFile(logPath)
	require.NoError(t, err)
	return string(b)
}

func TestRefusedBeforeHandshakeIsNotAnError(t *testing.T) {
	out := handshakeLog(t, func(c net.Conn) { c.Close() })
	require.NotContains(t, out, "ERRO")
	require.Contains(t, out, "Handshake failed")
}

func TestRefusedAfterReadingIsNotAnError(t *testing.T) {
	out := handshakeLog(t, func(c net.Conn) {
		buf := make([]byte, 1)
		c.Read(buf)
		c.Close()
	})
	require.NotContains(t, out, "ERRO")
}

func TestGarbageHandshakeIsAnError(t *testing.T) {
	out := handshakeLog(t, func(c net.Conn) {
		defer c.Close()
		done := make(chan struct{})
		go func() {
			io.Copy(io.Discard, c)
			close(done)
		}()
		junk := make([]byte, 1<<16)
		rand.Reader.Read(junk)
		c.Write(junk)
		<-done
	})
	require.True(t, strings.Contains(out, "ERRO") && strings.Contains(out, "Handshake failed"), out)
}
