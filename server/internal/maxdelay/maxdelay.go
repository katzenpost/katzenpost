// SPDX-License-Identifier: AGPL-3.0-only

package maxdelay

import (
	"time"

	"github.com/katzenpost/katzenpost/common"
)

const (
	BuiltinMu  = 0.001
	WildFactor = 4
)

func BuiltinMs() uint64 {
	return common.SafetyCap(BuiltinMu)
}

func Builtin() time.Duration {
	return time.Duration(BuiltinMs()) * time.Millisecond
}

func Wild(ms uint64) bool {
	builtin := BuiltinMs()
	return ms > builtin*WildFactor || ms*WildFactor < builtin
}

func Effective(consensusMs uint64, fallbackMs int, ceiling time.Duration) (limit time.Duration, fromConsensus bool) {
	fromConsensus = consensusMs != 0
	ms := consensusMs
	if !fromConsensus {
		ms = BuiltinMs()
		if fallbackMs > 0 {
			ms = uint64(fallbackMs)
		}
	}
	if ms > uint64(ceiling/time.Millisecond) {
		return ceiling, fromConsensus
	}
	return time.Duration(ms) * time.Millisecond, fromConsensus
}

func Source(fromConsensus bool) string {
	if fromConsensus {
		return "consensus"
	}
	return "fallback"
}
