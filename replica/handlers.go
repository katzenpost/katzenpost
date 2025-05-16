// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/sign/ed25519"

	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/replica/common"
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

	replicaEpoch, _, _ := common.ReplicaNow()
	replicaPrivateKeypair, err := c.l.server.envelopeKeys.GetKeypair(replicaEpoch)
	if err != nil {
		c.log.Errorf("handleReplicaMessage envelopeKeys.GetKeypair failed: %s", err)
		return nil
	}
	requestRaw, err := scheme.Decapsulate(replicaPrivateKeypair.PrivateKey, ct)
	if err != nil {
		c.log.Errorf("handleReplicaMessage Decapsulate failed: %s", err)
		errReply := &commands.ReplicaMessageReply{
			ErrorCode: replicaMessageReplyDecapsulationFailure,
		}
		return errReply
	}
	cmds := commands.NewStorageReplicaCommands(c.geo, nikeScheme)
	myCmd, err := cmds.FromBytes(requestRaw)
	if err != nil {
		c.log.Errorf("handleReplicaMessage Decapsulate failed: %s", err)
		errReply := &commands.ReplicaMessageReply{
			ErrorCode: replicaMessageReplyCommandParseFailure,
		}
		return errReply
	}
	envelopeHash := blake2b.Sum256(replicaMessage.SenderEPubKey[:])
	keypair, err := c.l.server.envelopeKeys.GetKeypair(replicaEpoch)
	if err != nil {
		c.log.Errorf("handleReplicaMessage failed to get envelope keypair: %s", err)
		return &commands.ReplicaMessageReply{
			Cmds:          commands.NewStorageReplicaCommands(c.geo, nikeScheme),
			ErrorCode:     2, // non-zero means failure.
			EnvelopeHash:  &envelopeHash,
			EnvelopeReply: []byte{},
		}
	}
	senderpubkey, err := nikeScheme.UnmarshalBinaryPublicKey(replicaMessage.SenderEPubKey[:])
	if err != nil {
		c.log.Errorf("handleReplicaMessage failed to unmarshal SenderEPubKey: %s", err)
		return &commands.ReplicaMessageReply{
			Cmds:          commands.NewStorageReplicaCommands(c.geo, nikeScheme),
			ErrorCode:     1, // non-zero means failure.
			EnvelopeHash:  &envelopeHash,
			EnvelopeReply: []byte{},
		}
	}

	doc := c.l.server.pkiWorker.PKIDocument()
	replicaID, err := doc.GetReplicaIDByIdentityKey(c.l.server.identityPublicKey)
	if err != nil {
		c.log.Errorf("handleReplicaMessage failed to get our own replica ID: %s", err)
		return &commands.ReplicaMessageReply{
			Cmds:          commands.NewStorageReplicaCommands(c.geo, nikeScheme),
			ErrorCode:     3, // non-zero means failure.
			EnvelopeHash:  &envelopeHash,
			EnvelopeReply: []byte{},
		}
	}

	switch myCmd := myCmd.(type) {
	case *common.ReplicaRead:
		readReply := c.handleReplicaRead(myCmd)
		replyInnerMessage := common.ReplicaMessageReplyInnerMessage{
			ReplicaReadReply: readReply,
		}
		replyInnerMessageBlob := replyInnerMessage.Bytes()
		envelopeReply := scheme.EnvelopeReply(keypair.PrivateKey, senderpubkey, replyInnerMessageBlob)
		return &commands.ReplicaMessageReply{
			Cmds:          commands.NewStorageReplicaCommands(c.geo, nikeScheme),
			ErrorCode:     0, // Zero means success.
			EnvelopeHash:  &envelopeHash,
			EnvelopeReply: envelopeReply,
			ReplicaID:     replicaID,
		}
	case *commands.ReplicaWrite:
		writeReply := c.handleReplicaWrite(myCmd)
		c.l.server.connector.DispatchReplication(myCmd)
		replyInnerMessage := common.ReplicaMessageReplyInnerMessage{
			ReplicaWriteReply: writeReply,
		}
		replyInnerMessageBlob := replyInnerMessage.Bytes()
		envelopeReply := scheme.EnvelopeReply(keypair.PrivateKey, senderpubkey, replyInnerMessageBlob)
		return &commands.ReplicaMessageReply{
			Cmds:          commands.NewStorageReplicaCommands(c.geo, nikeScheme),
			ErrorCode:     0, // Zero means success.
			EnvelopeHash:  &envelopeHash,
			EnvelopeReply: envelopeReply,
			ReplicaID:     replicaID,
		}
	default:
		c.log.Error("BUG: handleReplicaMessage failed: invalid request was decrypted")
		return nil
	}
}

func (c *incomingConn) handleReplicaRead(replicaRead *common.ReplicaRead) *common.ReplicaReadReply {
	const (
		successCode = 0
		failCode    = 1
	)
	resp, err := c.l.server.state.handleReplicaRead(replicaRead)
	if err != nil {
		return &common.ReplicaReadReply{
			ErrorCode: failCode,
		}
	}
	return &common.ReplicaReadReply{
		ErrorCode: successCode,
		BoxID:     resp.BoxID,
		Signature: resp.Signature,
		Payload:   resp.Payload,
	}
}

func (c *incomingConn) handleReplicaWrite(replicaWrite *commands.ReplicaWrite) *commands.ReplicaWriteReply {
	const (
		successCode = 0
		failCode    = 1
	)

	s := ed25519.Scheme()
	verifyKey, err := s.UnmarshalBinaryPublicKey(replicaWrite.BoxID[:])
	if err != nil {
		c.log.Errorf("handleReplicaWrite failed: %v", err)
		return &commands.ReplicaWriteReply{
			ErrorCode: failCode,
		}
	}
	if !s.Verify(verifyKey, replicaWrite.Payload, replicaWrite.Signature[:], nil) {
		c.log.Errorf("handleReplicaWrite failed: %v", err)
		return &commands.ReplicaWriteReply{
			ErrorCode: failCode,
		}
	}
	err = c.l.server.state.handleReplicaWrite(replicaWrite)
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
