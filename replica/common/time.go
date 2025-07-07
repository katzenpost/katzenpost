// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"time"

	"github.com/katzenpost/katzenpost/core/epochtime"
)

// ReplicaEpochPeriod is the length of time of the Repica Epoch.
// Storage Replicas garbage collect their replica keys every Replica Epoch.
const ReplicaEpochPeriod = 7 * (24 * time.Hour)

// ReplicaNow returns the current Replica Epoch, time since the start of the
// current epoch, and time till the next epoch for a weekly epoch duration.
func ReplicaNow() (current uint64, elapsed, till time.Duration) {
	fromEpoch := time.Now().Sub(epochtime.Epoch)
	if fromEpoch < 0 {
		panic("epochtime: BUG: time appears to predate the epoch")
	}

	current = uint64(fromEpoch / ReplicaEpochPeriod)
	base := epochtime.Epoch.Add(time.Duration(current) * ReplicaEpochPeriod)
	elapsed = time.Now().Sub(base)
	till = base.Add(ReplicaEpochPeriod).Sub(time.Now())
	return
}

// ConvertNormalToReplicaEpoch converts a 20-minute epoch number to a weekly replica epoch.
func ConvertNormalToReplicaEpoch(normalEpoch uint64) uint64 {
	return (normalEpoch * uint64(epochtime.Period)) / uint64(ReplicaEpochPeriod)
}
