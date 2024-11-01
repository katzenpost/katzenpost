// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func (c *incomingConn) onReplicaCommand(rawCmd commands.Command) (commands.Command, bool) {
	switch cmd := rawCmd.(type) {
	case *commands.NoOp:
		c.log.Debugf("Received NoOp from peer.")
		return nil, true
	case *commands.Disconnect:
		c.log.Debugf("Received disconnect from peer.")
		return nil, false
	case *commands.ReplicaWrite:
		c.log.Debugf("Received ReplicaWrite from peer.")
		resp := c.handleReplicaWrite(cmd)
		return resp, true
	case *commands.ReplicaMessage:
		c.log.Debugf("Received ReplicaMessage from peer.")
		resp := c.handleReplicaMessage(cmd)
		return resp, true
	default:
		c.log.Debugf("Received unexpected command: %T", cmd)
		return nil, false
	}
	// not reached
}

func (c *incomingConn) handleReplicaMessage(replicaMessage *commands.ReplicaMessage) commands.Command {
	nikeScheme := schemes.ByName(c.l.server.cfg.ReplicaNIKEScheme)
	scheme := mkem.NewScheme(nikeScheme)
	ct, err := mkem.CiphertextFromBytes(scheme, replicaMessage.Ciphertext)
	if err != nil {
		c.log.Errorf("handleReplicaMessage CiphertextFromBytes failed: %s", err)
		return nil
	}

	replicaEpoch, _, _ := ReplicaNow()
	replicaPrivateKeypair, err := c.l.server.envelopeKeys.GetKeypair(replicaEpoch)
	if err != nil {
		c.log.Errorf("handleReplicaMessage envelopeKeys.GetKeypair failed: %s", err)
		return nil
	}
	requestRaw, err := scheme.Decapsulate(replicaPrivateKeypair.PrivateKey, ct.Envelope)
	if err != nil {
		c.log.Errorf("handleReplicaMessage Decapsulate failed: %s", err)
		errReply := &commands.ReplicaMessageReply{
			ErrorCode: replicaMessageReplyDecapsulationFailure,
		}
		return errReply
	}
	cmds := commands.NewStorageReplicaCommands(c.geo)
	myCmd, err := cmds.FromBytes(requestRaw)
	if err != nil {
		c.log.Errorf("handleReplicaMessage Decapsulate failed: %s", err)
		errReply := &commands.ReplicaMessageReply{
			ErrorCode: replicaMessageReplyCommandParseFailure,
		}
		return errReply
	}
	switch myCmd := myCmd.(type) {
	case *commands.ReplicaRead:
		replyPayload := c.handleReplicaRead(myCmd).ToBytes()
		envelopeHash := blake2b.Sum256(replicaMessage.SenderEPubKey[:])
		senderpubkey, err := nikeScheme.UnmarshalBinaryPublicKey(replicaMessage.SenderEPubKey[:])
		if err != nil {
			c.log.Errorf("handleReplicaMessage failed to unmarshal SenderEPubKey: %s", err)
			return &commands.ReplicaMessageReply{
				Cmds:          commands.NewStorageReplicaCommands(c.geo),
				ErrorCode:     1, // One means failure.
				EnvelopeHash:  &envelopeHash,
				EnvelopeReply: []byte{},
			}
		}
		keypair, err := c.l.server.envelopeKeys.GetKeypair(replicaEpoch)
		if err != nil {
			c.log.Errorf("handleReplicaMessage failed to get envelope keypair: %s", err)
			return &commands.ReplicaMessageReply{
				Cmds:          commands.NewStorageReplicaCommands(c.geo),
				ErrorCode:     1, // One means failure.
				EnvelopeHash:  &envelopeHash,
				EnvelopeReply: []byte{},
			}
		}
		envelopeReply := scheme.EnvelopeReply(keypair.PrivateKey, senderpubkey, replyPayload)

		return &commands.ReplicaMessageReply{
			Cmds:          commands.NewStorageReplicaCommands(c.geo),
			ErrorCode:     0, // Zero means success.
			EnvelopeHash:  &envelopeHash,
			EnvelopeReply: envelopeReply,
		}
	case *commands.ReplicaWrite:
		c.handleReplicaWrite(myCmd)
		c.l.server.connector.DispatchReplication(myCmd)
		return nil
	default:
		c.log.Error("handleReplicaMessage failed: invalid request was decrypted")
		return nil
	}
}

func (c *incomingConn) handleReplicaRead(replicaRead *commands.ReplicaRead) *commands.ReplicaReadReply {
	const (
		successCode = 0
		failCode    = 1
	)
	resp, err := c.l.server.state.handleReplicaRead(replicaRead)
	if err != nil {
		return &commands.ReplicaReadReply{
			ErrorCode: failCode,
		}
	}
	return &commands.ReplicaReadReply{
		Cmds:      commands.NewStorageReplicaCommands(c.geo),
		Geo:       c.geo,
		ErrorCode: successCode,
		BoxID:     resp.BoxID,
		Signature: resp.Signature,
		Payload:   resp.Payload,
	}
}

func (c *incomingConn) handleReplicaWrite(replicaWrite *commands.ReplicaWrite) *commands.ReplicaWriteReply {
	// XXX FIXME(david): Use BACAP to verify if a signature authorizes the write to the specified box
	const (
		successCode = 0
		failCode    = 1
	)
	err := c.l.server.state.handleReplicaWrite(replicaWrite)
	if err != nil {
		c.log.Errorf("handleReplicaWrite failed: %v", err)
		return &commands.ReplicaWriteReply{
			ErrorCode: failCode,
		}
	}
	return &commands.ReplicaWriteReply{
		ErrorCode: successCode,
	}
}
