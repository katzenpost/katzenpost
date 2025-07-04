// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"crypto/hmac"
	"fmt"
	"time"

	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/sign/ed25519"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/pigeonhole"
	pgeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
)

// createReplicaMessageReply creates a ReplicaMessageReply with proper PigeonholeGeometry
func (c *incomingConn) createReplicaMessageReply(nikeScheme string, errorCode uint8, envelopeHash *[32]byte, envelopeReply []byte, replicaID uint8, isRead bool) *commands.ReplicaMessageReply {
	scheme := schemes.ByName(nikeScheme)
	pigeonholeGeo, err := pgeo.NewGeometryFromSphinx(c.geo, scheme)
	if err != nil {
		// This should not happen in normal operation, but if it does, create without geometry
		c.log.Errorf("Failed to create pigeonhole geometry: %v", err)
		return &commands.ReplicaMessageReply{
			Cmds:          commands.NewStorageReplicaCommands(c.geo, scheme),
			ErrorCode:     errorCode,
			EnvelopeHash:  envelopeHash,
			EnvelopeReply: envelopeReply,
			ReplicaID:     replicaID,
			IsRead:        isRead,
		}
	}

	return &commands.ReplicaMessageReply{
		Cmds:               commands.NewStorageReplicaCommands(c.geo, scheme),
		PigeonholeGeometry: pigeonholeGeo,
		ErrorCode:          errorCode,
		EnvelopeHash:       envelopeHash,
		EnvelopeReply:      envelopeReply,
		ReplicaID:          replicaID,
		IsRead:             isRead,
	}
}

func (c *incomingConn) onReplicaCommand(rawCmd commands.Command) (commands.Command, bool) {
	c.log.Debugf("onReplicaCommand received command type: %T with value: %+v", rawCmd, rawCmd)
	switch cmd := rawCmd.(type) {
	case *commands.NoOp:
		c.log.Debug("Received NoOp from peer")
		return nil, true
	case *commands.Disconnect:
		c.log.Debug("Received disconnect from peer")
		return nil, false
	case *commands.ReplicaDecoy:
		c.log.Debug("Received ReplicaDecoy from peer")
		return nil, true
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
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, envelopeHash, []byte{}, 0, false)
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
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, envelopeHash, []byte{}, 0, false)
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
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInvalidEpoch, envelopeHash, []byte{}, 0, false)
	}
	// Use the ephemeralPublicKey we already unmarshaled earlier
	senderpubkey := ephemeralPublicKey

	doc := c.l.server.PKIWorker.PKIDocument()
	if doc == nil {
		c.log.Error("handleReplicaMessage failed: no PKI document available")
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInvalidEpoch, envelopeHash, []byte{}, 0, false)
	}
	replicaID, err := doc.GetReplicaIDByIdentityKey(c.l.server.identityPublicKey)
	if err != nil {
		c.log.Errorf("handleReplicaMessage failed to get our own replica ID: %s", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, envelopeHash, []byte{}, 0, false)
	}

	switch {
	case msg.ReadMsg != nil:
		myCmd := msg.ReadMsg
		c.log.Debugf("Processing decrypted ReplicaRead command for BoxID: %x", myCmd.BoxID)

		// use sharding scheme to determine if BoxID belongs to this replica or another replica
		shards, err := replicaCommon.GetShards(&myCmd.BoxID, doc)
		if err != nil {
			c.log.Errorf("handleReplicaMessage failed to get shards: %s", err)
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, envelopeHash, []byte{}, 0, false)
		}

		// Log shard information for debugging
		shardNames := make([]string, len(shards))
		for i, shard := range shards {
			shardNames[i] = shard.Name
		}
		c.log.Debugf("BoxID %x is assigned to shards: %v", myCmd.BoxID, shardNames)

		// Check if this replica is one of the shards
		isShard := false
		myIdentityKey, err := c.l.server.identityPublicKey.MarshalBinary()
		if err != nil {
			c.log.Errorf("handleReplicaMessage failed to marshal identity key: %s", err)
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, envelopeHash, []byte{}, 0, false)
		}
		for _, shard := range shards {
			if hmac.Equal(shard.IdentityKey, myIdentityKey) {
				isShard = true
				break
			}
		}

		if isShard {
			c.log.Debugf("This replica IS a shard for BoxID %x - handling read locally", myCmd.BoxID)
			readReply := c.handleReplicaRead(myCmd)
			replyInnerMessage := pigeonhole.ReplicaMessageReplyInnerMessage{
				ReadReply: readReply,
			}
			replyInnerMessageBlob := replyInnerMessage.Bytes()
			envelopeReply := scheme.EnvelopeReply(keypair.PrivateKey, senderpubkey, replyInnerMessageBlob)
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, readReply.ErrorCode, envelopeHash, envelopeReply.Envelope, replicaID, true)
		}

		// This replica is NOT a shard for the BoxID, so we need to proxy the request to the correct replica
		// and send the reply back to the courier:
		c.log.Debugf("This replica is NOT a shard for BoxID %x - PROXYING read request to appropriate shard", myCmd.BoxID)
		reply, err := c.proxyReadRequest(myCmd, shards)
		if err != nil {
			c.log.Errorf("Proxy read request failed: %s", err)
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, envelopeHash, []byte{}, 0, false)
		}
		c.log.Debugf("Successfully completed proxy read request for BoxID %x", myCmd.BoxID)
		return reply
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
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, writeReply.ErrorCode, envelopeHash, envelopeReply.Envelope, replicaID, false)
	default:
		c.log.Error("BUG: handleReplicaMessage failed: invalid request was decrypted")
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, envelopeHash, []byte{}, 0, false)
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

// proxyReadRequest forwards a read request to the appropriate shard replica
// and returns the reply that should be sent back to the courier
func (c *incomingConn) proxyReadRequest(replicaRead *pigeonhole.ReplicaRead, shards []*pki.ReplicaDescriptor) (*commands.ReplicaMessageReply, error) {
	c.log.Debugf("Proxying read request for BoxID: %x to %d shards", replicaRead.BoxID, len(shards))

	// Get our own identity key to exclude ourselves from the target shards
	myIdentityKey, err := c.l.server.identityPublicKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal identity key: %v", err)
	}

	// Find the first shard that is not ourselves
	var targetShard *pki.ReplicaDescriptor
	for _, shard := range shards {
		if !hmac.Equal(shard.IdentityKey, myIdentityKey) {
			targetShard = shard
			break
		}
	}

	if targetShard == nil {
		return nil, fmt.Errorf("no suitable target shard found")
	}

	c.log.Debugf("Proxying read request to replica: %s", targetShard.Name)

	// Create a ReplicaMessage to send to the target replica
	nikeScheme := schemes.ByName(c.l.server.cfg.ReplicaNIKEScheme)
	scheme := mkem.NewScheme(nikeScheme)

	// Get the current epoch for envelope keys
	doc := c.l.server.PKIWorker.PKIDocument()
	if doc == nil {
		return nil, fmt.Errorf("no PKI document available")
	}
	replicaEpoch := doc.Epoch

	// Create the inner message containing the read request
	innerMessage := pigeonhole.ReplicaInnerMessage{
		ReadMsg: replicaRead,
	}
	innerMessageBlob := innerMessage.Bytes()

	// Get the target replica's envelope public key
	// Try current epoch first, then next epoch
	var targetEnvelopeKeyBytes []byte
	var targetEnvelopeKey nike.PublicKey
	var keyEpoch uint64

	targetEnvelopeKeyBytes, exists := targetShard.EnvelopeKeys[replicaEpoch]
	if exists {
		keyEpoch = replicaEpoch
	} else {
		// Try next epoch
		targetEnvelopeKeyBytes, exists = targetShard.EnvelopeKeys[replicaEpoch+1]
		if exists {
			keyEpoch = replicaEpoch + 1
		}
	}

	if !exists {
		// Log available epochs for debugging
		availableEpochs := make([]uint64, 0, len(targetShard.EnvelopeKeys))
		for epoch := range targetShard.EnvelopeKeys {
			availableEpochs = append(availableEpochs, epoch)
		}
		return nil, fmt.Errorf("no envelope key found for target replica %s at epoch %d or %d, available epochs: %v",
			targetShard.Name, replicaEpoch, replicaEpoch+1, availableEpochs)
	}

	targetEnvelopeKey, err = nikeScheme.UnmarshalBinaryPublicKey(targetEnvelopeKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal target envelope key for epoch %d: %v", keyEpoch, err)
	}

	c.log.Debugf("Using envelope key for target replica %s at epoch %d", targetShard.Name, keyEpoch)

	// Encapsulate the message for the target replica using MKEM
	mkemPrivateKey, envelope := scheme.Encapsulate([]nike.PublicKey{targetEnvelopeKey}, innerMessageBlob)

	// Create the ReplicaMessage command
	replicaMessage := &commands.ReplicaMessage{
		Cmds:               commands.NewStorageReplicaCommands(c.geo, nikeScheme),
		PigeonholeGeometry: nil, // Will be set by the command system if needed
		Scheme:             nikeScheme,
		SenderEPubKey:      envelope.EphemeralPublicKey.Bytes(),
		DEK:                envelope.DEKCiphertexts[0],
		Ciphertext:         envelope.Envelope,
	}

	// Get the envelope hash for correlation
	envelopeHash := replicaMessage.EnvelopeHash()

	// Register this request for response correlation, storing the MKEM private key for decryption
	timeout := 30 * time.Second // 30 second timeout for proxy requests
	responseCh := c.l.server.proxyRequestManager.RegisterRequest(*envelopeHash, timeout, mkemPrivateKey, targetEnvelopeKey)

	// Calculate the target replica's identity hash for routing
	idHash := blake2b.Sum256(targetShard.IdentityKey)

	// Send the command to the target replica via the connector
	c.l.server.connector.DispatchCommand(replicaMessage, &idHash)

	c.log.Debugf("Sent proxy request to %s, waiting for response with envelope hash: %x", targetShard.Name, envelopeHash)

	// Wait for the response with timeout
	select {
	case reply := <-responseCh:
		if reply == nil {
			c.log.Errorf("Received nil reply for proxy request to %s", targetShard.Name)
			return c.createReplicaMessageReply(
				c.l.server.cfg.ReplicaNIKEScheme,
				pigeonhole.ReplicaErrorInternalError,
				envelopeHash,
				[]byte{},
				0,
				true,
			), nil
		}

		c.log.Debugf("Received proxy reply from %s with error code: %d", targetShard.Name, reply.ErrorCode)

		// Return the reply we received from the target replica
		// The envelope reply is already encrypted for the original courier
		return reply, nil

	case <-time.After(timeout):
		c.log.Errorf("Timeout waiting for proxy response from %s", targetShard.Name)
		return c.createReplicaMessageReply(
			c.l.server.cfg.ReplicaNIKEScheme,
			pigeonhole.ReplicaErrorInternalError, // Use internal error for timeout
			envelopeHash,
			[]byte{},
			0,
			true,
		), nil
	}
}
