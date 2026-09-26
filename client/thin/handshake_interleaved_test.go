// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"net"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/rand"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func newHandshakeTestClient(t *testing.T, conn net.Conn) *ThinClient {
	sphinxGeo, pigeonGeo := newTestGeometries()
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	tc := &ThinClient{
		cfg:         &Config{},
		sphinxGeo:   sphinxGeo,
		pigeonGeo:   pigeonGeo,
		log:         logBackend.GetLogger("thinclient"),
		conn:        conn,
		eventSink:   make(chan Event, 2),
		drainAdd:    make(chan chan Event),
		drainRemove: make(chan chan Event),
		pkiDocCache: make(map[uint64]*cpki.Document),
	}
	_, err = rand.Reader.Read(tc.instanceToken[:])
	require.NoError(t, err)
	return tc
}

func pkiDocResponse(t *testing.T, epoch uint64) *Response {
	docBytes, err := cbor.Marshal(&cpki.Document{Epoch: epoch})
	require.NoError(t, err)
	return &Response{NewPKIDocumentEvent: &NewPKIDocumentEvent{Payload: docBytes}}
}

func TestDialAcceptsAPKIDocumentBeforeTheSessionTokenReply(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	tc := newHandshakeTestClient(t, client)

	served := make(chan struct{})
	go func() {
		defer close(served)
		sendResponse(t, server, &Response{
			ConnectionStatusEvent: &ConnectionStatusEvent{
				IsConnected: true, SphinxGeometry: tc.sphinxGeo, PigeonholeGeometry: tc.pigeonGeo,
			},
		})
		sendResponse(t, server, pkiDocResponse(t, 100))
		if _, err := readRequest(server); err != nil {
			return
		}
		sendResponse(t, server, pkiDocResponse(t, 101))
		sendResponse(t, server, &Response{SessionTokenReply: &SessionTokenReply{}})
	}()

	require.NoError(t, tc.Dial())
	defer tc.Disconnect()
	<-served
	require.Contains(t, tc.pkiDocCache, uint64(101))
}
func TestDialFailsWhenNoSessionTokenReplyArrives(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	tc := newHandshakeTestClient(t, client)

	served := make(chan struct{})
	go func() {
		defer close(served)
		sendResponse(t, server, &Response{
			ConnectionStatusEvent: &ConnectionStatusEvent{
				IsConnected: true, SphinxGeometry: tc.sphinxGeo, PigeonholeGeometry: tc.pigeonGeo,
			},
		})
		sendResponse(t, server, pkiDocResponse(t, 200))
		if _, err := readRequest(server); err != nil {
			return
		}
		for i := 0; i < 16; i++ {
			sendResponse(t, server, pkiDocResponse(t, uint64(300+i)))
		}
	}()

	err := tc.Dial()
	require.Error(t, err)
	require.Contains(t, err.Error(), "SessionTokenReply")
	<-served
}
