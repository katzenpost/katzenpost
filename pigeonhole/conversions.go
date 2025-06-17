// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package pigeonhole - conversion functions between trunnel message types and wire command types
package pigeonhole

import (
	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// TrunnelReplicaWriteToWireCommand converts a trunnel ReplicaWrite to a wire commands.ReplicaWrite
// If cmds is provided, it will be set for wire protocol use. If nil, Cmds will be nil (for embedding).
func TrunnelReplicaWriteToWireCommand(trunnelWrite *ReplicaWrite, cmds *commands.Commands) *commands.ReplicaWrite {
	if trunnelWrite == nil {
		return nil
	}

	// Convert array types to pointer types
	boxID := &[bacap.BoxIDSize]byte{}
	copy(boxID[:], trunnelWrite.BoxID[:])

	signature := &[bacap.SignatureSize]byte{}
	copy(signature[:], trunnelWrite.Signature[:])

	return &commands.ReplicaWrite{
		Cmds:      cmds, // Set for wire protocol use, nil for embedding
		BoxID:     boxID,
		Signature: signature,
		Payload:   trunnelWrite.Payload,
	}
}

// WireCommandToTrunnelReplicaWrite converts a wire commands.ReplicaWrite to a trunnel ReplicaWrite
func WireCommandToTrunnelReplicaWrite(wireWrite *commands.ReplicaWrite) *ReplicaWrite {
	if wireWrite == nil {
		return nil
	}

	trunnelWrite := &ReplicaWrite{
		PayloadLen: uint32(len(wireWrite.Payload)),
		Payload:    make([]uint8, len(wireWrite.Payload)),
	}

	// Convert pointer types to array types
	copy(trunnelWrite.BoxID[:], wireWrite.BoxID[:])
	copy(trunnelWrite.Signature[:], wireWrite.Signature[:])
	copy(trunnelWrite.Payload, wireWrite.Payload)

	return trunnelWrite
}

// TrunnelReplicaWriteReplyToWireCommand converts a trunnel ReplicaWriteReply to a wire commands.ReplicaWriteReply
// If cmds is provided, it will be set for wire protocol use. If nil, Cmds will be nil (for embedding).
func TrunnelReplicaWriteReplyToWireCommand(trunnelReply *ReplicaWriteReply, cmds *commands.Commands) *commands.ReplicaWriteReply {
	if trunnelReply == nil {
		return nil
	}

	return &commands.ReplicaWriteReply{
		Cmds:      cmds, // Set for wire protocol use, nil for embedding
		ErrorCode: trunnelReply.ErrorCode,
	}
}

// WireCommandToTrunnelReplicaWriteReply converts a wire commands.ReplicaWriteReply to a trunnel ReplicaWriteReply
func WireCommandToTrunnelReplicaWriteReply(wireReply *commands.ReplicaWriteReply) *ReplicaWriteReply {
	if wireReply == nil {
		return nil
	}

	return &ReplicaWriteReply{
		ErrorCode: wireReply.ErrorCode,
	}
}
