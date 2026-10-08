// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
)

func send(conn net.Conn, r *thin.Response) error {
	b, err := cbor.Marshal(r)
	if err != nil {
		return err
	}
	prefix := make([]byte, 4)
	binary.BigEndian.PutUint32(prefix, uint32(len(b)))
	_, err = conn.Write(append(prefix, b...))
	return err
}

func receive(conn net.Conn) (*thin.Request, error) {
	prefix := make([]byte, 4)
	if _, err := io.ReadFull(conn, prefix); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint32(prefix))
	if _, err := io.ReadFull(conn, b); err != nil {
		return nil, err
	}
	req := &thin.Request{}
	return req, cbor.Unmarshal(b, req)
}

func fakeDaemon(t *testing.T, payload []byte, code uint8) string {
	dir, err := os.MkdirTemp("", "bw")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	l, err := net.Listen("unix", sock)
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })

	sphinxGeo := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 2000, true, 5)
	pigeonGeo := pigeonholeGeo.NewGeometry(1000, nikeSchemes.ByName("x25519"))
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if send(conn, &thin.Response{ConnectionStatusEvent: &thin.ConnectionStatusEvent{
			IsConnected: true, SphinxGeometry: sphinxGeo, PigeonholeGeometry: pigeonGeo,
		}}) != nil {
			return
		}
		if send(conn, &thin.Response{NewPKIDocumentEvent: &thin.NewPKIDocumentEvent{}}) != nil {
			return
		}
		if _, err := receive(conn); err != nil {
			return
		}
		if send(conn, &thin.Response{SessionTokenReply: &thin.SessionTokenReply{}}) != nil {
			return
		}
		for {
			req, err := receive(conn)
			if err != nil || req.ThinClose != nil {
				return
			}
			if req.GetPKIDocument == nil {
				continue
			}
			if send(conn, &thin.Response{GetPKIDocumentReply: &thin.GetPKIDocumentReply{
				QueryID: req.GetPKIDocument.QueryID, Payload: payload, ErrorCode: code,
			}}) != nil {
				return
			}
		}
	}()

	cfgFile := filepath.Join(dir, "thinclient.toml")
	require.NoError(t, os.WriteFile(cfgFile, []byte("[Dial]\n  [Dial.Unix]\n    Address = \""+sock+"\"\n"), 0600))
	return cfgFile
}

func signedDocument(t *testing.T, epoch uint64) []byte {
	scheme := signSchemes.ByName(testSchemeName)
	pub, priv, err := scheme.GenerateKey()
	require.NoError(t, err)
	raw, err := cpki.SignDocument(priv, pub, &cpki.Document{Epoch: epoch, LambdaP: 0.001, LambdaL: 0.0005, PKISignatureScheme: scheme.Name()})
	require.NoError(t, err)
	return raw
}

func TestRunFetchBandwidthPrintsTheEstimate(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	cfg := Config{Bandwidth: true, ConfigFile: fakeDaemon(t, signedDocument(t, epoch), thin.ThinClientSuccess), LogLevel: "ERROR"}
	out, err := captureStdout(t, func() error { return runFetch(cfg) })
	require.NoError(t, err)
	require.Contains(t, out, fmt.Sprintf("Estimated bandwidth for epoch %d with decoy traffic: 1.50 packets/s", epoch))
}

func TestRunFetchBandwidthWithoutADocumentFails(t *testing.T) {
	cfg := Config{Bandwidth: true, ConfigFile: fakeDaemon(t, nil, thin.ThinClientErrorConnectionLost), LogLevel: "ERROR"}
	out, err := captureStdout(t, func() error { return runFetch(cfg) })
	require.ErrorContains(t, err, "no consensus document to estimate from")
	require.NotContains(t, out, "Estimated bandwidth")
}

func TestRunFetchBandwidthRejectsAnUnparsableDocument(t *testing.T) {
	cfg := Config{Bandwidth: true, ConfigFile: fakeDaemon(t, []byte("not a document"), thin.ThinClientSuccess), LogLevel: "ERROR"}
	out, err := captureStdout(t, func() error { return runFetch(cfg) })
	require.Error(t, err)
	require.NotContains(t, out, "Estimated bandwidth")
}
