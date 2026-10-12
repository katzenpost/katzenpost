// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"time"

	"github.com/katzenpost/katzenpost/server/internal/packet"
)

const defaultPreDelayQueueSize = 10 * InboundPacketsChannelSize

type preDelay struct {
	maxLen int
}

func newPreDelay(release func(*packet.Packet), maxLen int, drop func(*packet.Packet), fallbackMs int) *preDelay {
	return &preDelay{}
}

func (d *preDelay) setMaxDelay(consensusMs uint64) (limit time.Duration, fromConsensus, changed bool) {
	return 0, false, false
}

func (d *preDelay) len() int {
	return 0
}

func (d *preDelay) push(pkt *packet.Packet) bool {
	return false
}

func (d *preDelay) Halt() {
}
