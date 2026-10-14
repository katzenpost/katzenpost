// SPDX-License-Identifier: AGPL-3.0-only

package kaetzchen

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/cborplugin"
	"github.com/katzenpost/katzenpost/server/internal/packet"
)

func queuedPacket(t *testing.T, recipient [sConstants.RecipientIDLength]byte) *packet.Packet {
	g := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 2000, true, 5)
	pkt, err := packet.New(make([]byte, g.PacketLength), g)
	require.NoError(t, err)
	pkt.Recipient = &commands.Recipient{ID: recipient}
	return pkt
}

func stuckPluginWorker(t *testing.T, queue int) (*CBORPluginWorker, [sConstants.RecipientIDLength]byte, *cborplugin.Client) {
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	var recipient [sConstants.RecipientIDLength]byte
	copy(recipient[:], "+stuck")
	client := cborplugin.NewClient(logBackend, "stuck", "+stuck", nil, 0)
	k := &CBORPluginWorker{
		glue:        getGlue(logBackend, nil, nil, nil),
		log:         logBackend.GetLogger("stuck plugin test"),
		pluginChans: PluginChans{recipient: make(chan interface{}, queue)},
		clients:     []*cborplugin.Client{client},
		params:      make(map[string]map[string]interface{}),
	}
	t.Cleanup(k.Halt)
	return k, recipient, client
}

func TestFullPluginQueueDoesNotBlockDispatch(t *testing.T) {
	k, recipient, _ := stuckPluginWorker(t, 2)
	for i := 0; i < 2; i++ {
		k.OnKaetzchen(queuedPacket(t, recipient))
	}
	pkt := queuedPacket(t, recipient)
	done := make(chan struct{})
	go func() {
		k.OnKaetzchen(pkt)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.Fail(t, "OnKaetzchen blocked on a full plugin queue")
		return
	}
	require.Nil(t, pkt.Recipient, "dropped packet was not disposed")
}

func TestUnregisterDisposesQueuedPackets(t *testing.T) {
	k, recipient, client := stuckPluginWorker(t, 4)
	queued := make([]*packet.Packet, 3)
	for i := range queued {
		queued[i] = queuedPacket(t, recipient)
		k.pluginChans[recipient] <- queued[i]
	}
	k.unregister(recipient, client)
	for i, pkt := range queued {
		require.Nilf(t, pkt.Recipient, "packet %d left in the queue of an unregistered plugin", i)
	}
	pkt := queuedPacket(t, recipient)
	k.OnKaetzchen(pkt)
	require.Nil(t, pkt.Recipient, "packet for an unregistered plugin was not disposed")
}

func TestShutdownDisposesIncomingPackets(t *testing.T) {
	k, recipient, _ := stuckPluginWorker(t, 2)
	k.Halt()
	pkt := queuedPacket(t, recipient)
	k.OnKaetzchen(pkt)
	require.Nil(t, pkt.Recipient, "packet arriving after halt was not disposed")
}
