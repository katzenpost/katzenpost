// SPDX-FileCopyrightText: Copyright (C) 2024  David Anthony Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package commands

import (
	"encoding/binary"
	"fmt"
)

// NIKE scheme CTIDH1024-X25519 has 160 byte public keys
const HybridKeySize = 160

type ReplicaMessage struct {
	Cmds *Commands

	SenderEPubKey *[HybridKeySize]byte
	DEK           *[32]byte
	Ciphertext    []byte
}

// ToBytes serializes the NoOp and returns the resulting slice.
func (c *ReplicaMessage) ToBytes() []byte {
	out := make([]byte, cmdOverhead, cmdOverhead+32+len(c.Ciphertext))
	out[0] = byte(replicaMessage)
	binary.BigEndian.PutUint32(out[2:6], uint32(c.Length()-cmdOverhead))

	out = append(out, c.SenderEPubKey[:]...)
	out = append(out, c.DEK[:]...)
	out = append(out, c.Ciphertext...)

	return c.Cmds.padToMaxCommandSize(out, true)
}

func replicaMessageFromBytes(b []byte, cmds *Commands) (Command, error) {
	fmt.Println("replicaMessageFromBytes yoyo")
	c := new(ReplicaMessage)
	c.Cmds = cmds

	c.SenderEPubKey = &[160]byte{}
	copy(c.SenderEPubKey[:], b[:HybridKeySize])

	c.DEK = &[32]byte{}
	copy(c.DEK[:], b[HybridKeySize:HybridKeySize+32])

	// c.Cmds.geo.PacketLength
	c.Ciphertext = make([]byte, len(b[HybridKeySize+32:]))
	copy(c.Ciphertext, b[HybridKeySize+32:])

	return c, nil
}

func (c *ReplicaMessage) Length() int {
	// XXX TODO(David): Pick a more precise size.
	return cmdOverhead + HybridKeySize + 32 + c.Cmds.geo.PacketLength
}
