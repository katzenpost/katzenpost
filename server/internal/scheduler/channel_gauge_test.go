// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noprometheus

package scheduler

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/internal/instrument"
	"github.com/katzenpost/katzenpost/server/internal/packet"
)

func TestPipeWorkerReportsChannelUsage(t *testing.T) {
	func() {
		defer func() { recover() }()
		instrument.StartPrometheusListener(&mockGlue{})
	}()
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	sch := &scheduler{
		log:   logBackend.GetLogger("gauge test"),
		inCh:  make(chan interface{}, 4),
		outCh: NewBatchingChannel(64),
	}
	sch.Go(sch.pipeWorker)
	defer sch.Worker.Halt()

	g := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 2000, true, 5)
	pkt, err := packet.New(make([]byte, g.PacketLength), g)
	require.NoError(t, err)
	sch.inCh <- pkt
	require.Eventually(t, func() bool {
		_, _, found := instrument.ChannelGauge("scheduler_incoming")
		return found
	}, 5*time.Second, 10*time.Millisecond)
}
