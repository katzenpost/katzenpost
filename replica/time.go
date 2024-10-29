// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"time"

	"github.com/katzenpost/katzenpost/core/epochtime"
)

const ReplicaPeriod = 7 * 24 * time.Hour

// ReplicaNow returns the current replica-epoch, time since the start of the
// current epoch, and time till the next epoch for a weekly epoch duration.
func ReplicaNow() (current uint64, elapsed, till time.Duration) {
	fromEpoch := time.Now().Sub(epochtime.Epoch)
	if fromEpoch < 0 {
		panic("epochtime: BUG: time appears to predate the epoch")
	}

	current = uint64(fromEpoch / ReplicaPeriod)
	base := epochtime.Epoch.Add(time.Duration(current) * ReplicaPeriod)
	elapsed = time.Now().Sub(base)
	till = base.Add(ReplicaPeriod).Sub(time.Now())
	return
}

// ConvertNormalToReplicaEpoch converts a 20-minute epoch number to a weekly replica epoch.
func ConvertNormalToReplicaEpoch(normalEpoch uint64) uint64 {
	return (normalEpoch * uint64(epochtime.Period)) / uint64(ReplicaPeriod)
}

// ConvertReplicaToNormalEpoch converts a weekly replica epoch number to a 20-minute epoch.
func ConvertReplicaToNormalEpoch(replicaEpoch uint64) uint64 {
	return (replicaEpoch * uint64(ReplicaPeriod)) / uint64(epochtime.Period)
}
