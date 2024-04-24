// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package loops

import (
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
)

// SegmentIDSize is twice the size of a node id because
// a segment consists of two nodes.
const SegmentIDSize = constants.NodeIDLength * 2

// PacketlossHeatMap records heat map ratios for decoy loop packet loss statistics
// for the entire mix network.
type PacketlossHeatMap struct {
	// SegmentRatios is a map of ratio values indexed by segment ID.
	SegmentRatios map[[SegmentIDSize]byte]float64
}

// LoopStats for an individual mix node.
type LoopStats struct {
	// MixIdentityHash identifies the mix node which generated these
	// decoy loop packet loss statistics.
	MixIdentityHash *[32]byte

	// Epoch identifies the epoch corresponding to the statistics.
	Epoch uint64

	// SegmentRatios is a map of ratio values indexed by segment ID.
	SegmentRatios map[[SegmentIDSize]byte]float64
}
