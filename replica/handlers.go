// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/sign/ed25519"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"

	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/pigeonhole"
)

func (c *incomingConn) onReplicaCommand(rawCmd commands.Command) (commands.Command, bool) {
	c.log.Debugf("onReplicaCommand received command type: %T with value: %+v", rawCmd, rawCmd)
	switch cmd := rawCmd.(type) {
	case *commands.NoOp:
		c.log.Debug("Received NoOp from peer")
		return nil, true
	case *commands.Disconnect:
		c.log.Debug("Received disconnect from peer")
		return nil, false
	case *commands.ReplicaWrite:
		c.log.Debugf("Processing ReplicaWrite command for BoxID: %x", cmd.BoxID)
		// Convert wire command to trunnel type
		trunnelWrite := pigeonhole.WireCommandToTrunnelReplicaWrite(cmd)
		trunnelResp := c.handleReplicaWrite(trunnelWrite)
		// Convert trunnel response back to wire command
		resp := pigeonhole.TrunnelReplicaWriteReplyToWireCommand(trunnelResp, cmd.Cmds)
		return resp, true
	case *commands.ReplicaMessage:
		c.log.Debugf("Processing ReplicaMessage command with ciphertext length: %d", len(cmd.Ciphertext))
		resp := c.handleReplicaMessage(cmd)
		return resp, true
	default:
		c.log.Errorf("Received unexpected command type: %T", cmd)
		return nil, false
	}
	// not reached
}

// replicaMessage's are sent from the courier to the replica storage servers
func (c *incomingConn) handleReplicaMessage(replicaMessage *commands.ReplicaMessage) commands.Command {
	c.log.Debug("Starting handleReplicaMessage processing")
	nikeScheme := schemes.ByName(c.l.server.cfg.ReplicaNIKEScheme)
	scheme := mkem.NewScheme(nikeScheme)

	// Construct the MKEM ciphertext from the ReplicaMessage fields
	// The Ciphertext field contains only the envelope, not the full CBOR-encoded mkem.Ciphertext
	ephemeralPublicKey, err := nikeScheme.UnmarshalBinaryPublicKey(replicaMessage.SenderEPubKey)
	if err != nil {
		c.log.Errorf("handleReplicaMessage failed to unmarshal SenderEPubKey: %s", err)
		envelopeHash := replicaMessage.EnvelopeHash()
		return &commands.ReplicaMessageReply{
			Cmds:          commands.NewStorageReplicaCommands(c.geo, nikeScheme),
			ErrorCode:     pigeonhole.ReplicaErrorInternalError,
			EnvelopeHash:  envelopeHash,
			EnvelopeReply: []byte{},
		}
	}
	ct := &mkem.Ciphertext{
		EphemeralPublicKey: ephemeralPublicKey,
		DEKCiphertexts:     []*[mkem.DEKSize]byte{replicaMessage.DEK},
		Envelope:           replicaMessage.Ciphertext,
	}

	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	replicaPrivateKeypair, err := c.l.server.envelopeKeys.GetKeypair(replicaEpoch)
	if err != nil {
		c.log.Errorf("handleReplicaMessage envelopeKeys.GetKeypair failed: %s", err)
		return nil
	}
	c.log.Debug("Attempting to decapsulate message")
	requestRaw, err := scheme.Decapsulate(replicaPrivateKeypair.PrivateKey, ct)
	if err != nil {
		c.log.Errorf("handleReplicaMessage Decapsulate failed: %s", err)
		envelopeHash := replicaMessage.EnvelopeHash()
		errReply := &commands.ReplicaMessageReply{
			Cmds:          commands.NewStorageReplicaCommands(c.geo, nikeScheme),
			ErrorCode:     pigeonhole.ReplicaErrorInternalError,
			EnvelopeHash:  envelopeHash,
			ReplicaID:     0, // We don't have a valid replica ID in this error case
			EnvelopeReply: []byte{},
		}
		return errReply
	}

	c.log.Debug("Successfully decapsulated message, parsing command")
	msg, err := pigeonhole.ParseReplicaInnerMessage(requestRaw)
	if err != nil {
		panic(err)
	}
	c.log.Debug("Successfully parsed command")

	envelopeHash := replicaMessage.EnvelopeHash()

	keypair, err := c.l.server.envelopeKeys.GetKeypair(replicaEpoch)
	if err != nil {
		c.log.Errorf("handleReplicaMessage failed to get envelope keypair: %s", err)
		return &commands.ReplicaMessageReply{
			Cmds:          commands.NewStorageReplicaCommands(c.geo, nikeScheme),
			ErrorCode:     pigeonhole.ReplicaErrorInvalidEpoch,
			EnvelopeHash:  envelopeHash,
			EnvelopeReply: []byte{},
		}
	}
	// Use the ephemeralPublicKey we already unmarshaled earlier
	senderpubkey := ephemeralPublicKey

	doc := c.l.server.PKIWorker.PKIDocument()
	if doc == nil {
		c.log.Error("handleReplicaMessage failed: no PKI document available")
		return &commands.ReplicaMessageReply{
			Cmds:          commands.NewStorageReplicaCommands(c.geo, nikeScheme),
			ErrorCode:     pigeonhole.ReplicaErrorInvalidEpoch,
			EnvelopeHash:  envelopeHash,
			EnvelopeReply: []byte{},
		}
	}
	replicaID, err := doc.GetReplicaIDByIdentityKey(c.l.server.identityPublicKey)
	if err != nil {
		c.log.Errorf("handleReplicaMessage failed to get our own replica ID: %s", err)
		return &commands.ReplicaMessageReply{
			Cmds:          commands.NewStorageReplicaCommands(c.geo, nikeScheme),
			ErrorCode:     pigeonhole.ReplicaErrorInternalError,
			EnvelopeHash:  envelopeHash,
			EnvelopeReply: []byte{},
		}
	}

	switch {
	case msg.ReadMsg != nil:
		myCmd := msg.ReadMsg
		c.log.Debugf("Processing decrypted ReplicaRead command for BoxID: %x", myCmd.BoxID)
		readReply := c.handleReplicaRead(myCmd)
		replyInnerMessage := pigeonhole.ReplicaMessageReplyInnerMessage{
			ReadReply: readReply,
		}
		replyInnerMessageBlob := replyInnerMessage.Bytes()
		envelopeReply := scheme.EnvelopeReply(keypair.PrivateKey, senderpubkey, replyInnerMessageBlob)
		return &commands.ReplicaMessageReply{
			Cmds:          commands.NewStorageReplicaCommands(c.geo, nikeScheme),
			ErrorCode:     readReply.ErrorCode, // Use the actual read result error code
			EnvelopeHash:  envelopeHash,
			EnvelopeReply: envelopeReply.Envelope,
			ReplicaID:     replicaID,
			IsRead:        true,
		}
	case msg.WriteMsg != nil:
		myCmd := msg.WriteMsg
		c.log.Debugf("Processing decrypted ReplicaWrite command for BoxID: %x", myCmd.BoxID)
		writeReply := c.handleReplicaWrite(myCmd)
		// Convert trunnel type to wire command for replication
		cmds := commands.NewStorageReplicaCommands(c.geo, nikeScheme)
		wireCmd := pigeonhole.TrunnelReplicaWriteToWireCommand(myCmd, cmds)
		c.l.server.connector.DispatchReplication(wireCmd)
		replyInnerMessage := pigeonhole.ReplicaMessageReplyInnerMessage{
			WriteReply: writeReply,
		}
		replyInnerMessageBlob := replyInnerMessage.Bytes()
		envelopeReply := scheme.EnvelopeReply(keypair.PrivateKey, senderpubkey, replyInnerMessageBlob)
		return &commands.ReplicaMessageReply{
			Cmds:          commands.NewStorageReplicaCommands(c.geo, nikeScheme),
			ErrorCode:     writeReply.ErrorCode, // Use the actual write result error code
			EnvelopeHash:  envelopeHash,
			EnvelopeReply: envelopeReply.Envelope,
			ReplicaID:     replicaID,
			IsRead:        false,
		}
	default:
		c.log.Error("BUG: handleReplicaMessage failed: invalid request was decrypted")
		return &commands.ReplicaMessageReply{
			Cmds:          commands.NewStorageReplicaCommands(c.geo, nikeScheme),
			ErrorCode:     pigeonhole.ReplicaErrorInternalError,
			EnvelopeHash:  envelopeHash,
			EnvelopeReply: []byte{},
		}
	}
}

func (c *incomingConn) handleReplicaRead(replicaRead *pigeonhole.ReplicaRead) *pigeonhole.ReplicaReadReply {
	c.log.Debugf("Handling replica read request for BoxID: %x", replicaRead.BoxID)
	resp, err := c.l.server.state.handleReplicaRead(replicaRead)
	if err != nil {
		c.log.Errorf("Replica read failed: %v", err)
		// Map specific errors to specific error codes
		errorCode := pigeonhole.ReplicaErrorNotFound // Default to ReplicaErrorNotFound
		reply := &pigeonhole.ReplicaReadReply{
			ErrorCode: errorCode,
		}
		return reply
	}
	c.log.Debug("Replica read successful")
	reply := &pigeonhole.ReplicaReadReply{
		BoxID:      resp.BoxID,
		Signature:  resp.Signature,
		PayloadLen: uint32(len(resp.Payload)),
		Payload:    resp.Payload,
		ErrorCode:  pigeonhole.ReplicaErrorSuccess,
	}
	return reply
}

func (c *incomingConn) handleReplicaWrite(replicaWrite *pigeonhole.ReplicaWrite) *pigeonhole.ReplicaWriteReply {
	c.log.Debugf("Handling replica write request for BoxID: %x", replicaWrite.BoxID)
	s := ed25519.Scheme()
	verifyKey, err := s.UnmarshalBinaryPublicKey(replicaWrite.BoxID[:])
	if err != nil {
		c.log.Errorf("handleReplicaWrite failed to unmarshal BoxID as public key: %v", err)
		return &pigeonhole.ReplicaWriteReply{
			ErrorCode: pigeonhole.ReplicaErrorInvalidBoxID,
		}
	}
	if !s.Verify(verifyKey, replicaWrite.Payload, replicaWrite.Signature[:], nil) {
		c.log.Error("handleReplicaWrite signature verification failed")
		return &pigeonhole.ReplicaWriteReply{
			ErrorCode: pigeonhole.ReplicaErrorInvalidSignature,
		}
	}
	// Convert trunnel type to wire command for state handling
	nikeScheme := schemes.ByName(c.l.server.cfg.ReplicaNIKEScheme)
	cmds := commands.NewStorageReplicaCommands(c.l.server.cfg.SphinxGeometry, nikeScheme)
	wireWrite := pigeonhole.TrunnelReplicaWriteToWireCommand(replicaWrite, cmds)
	err = c.l.server.state.handleReplicaWrite(wireWrite)
	if err != nil {
		c.log.Errorf("handleReplicaWrite state update failed: %v", err)
		return &pigeonhole.ReplicaWriteReply{
			ErrorCode: pigeonhole.ReplicaErrorDatabaseError,
		}
	}
	c.log.Debug("Replica write successful")
	return &pigeonhole.ReplicaWriteReply{
		ErrorCode: pigeonhole.ReplicaErrorSuccess,
	}
}
