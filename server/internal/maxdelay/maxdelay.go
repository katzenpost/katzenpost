// SPDX-License-Identifier: AGPL-3.0-only

package maxdelay

import "time"

func Effective(consensusMs uint64, fallbackMs int, ceiling time.Duration) (limit time.Duration, fromConsensus bool) {
	fromConsensus = consensusMs != 0
	ms := consensusMs
	if !fromConsensus && fallbackMs > 0 {
		ms = uint64(fallbackMs)
	}
	if ms == 0 || ms > uint64(ceiling/time.Millisecond) {
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
