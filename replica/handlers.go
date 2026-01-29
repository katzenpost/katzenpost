// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/sign/ed25519"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"

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
		panic("we should always be able to derive a pigeonhole geometry object")
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

func (c *incomingConn) onReplicaCommand(rawCmd commands.Command) (*senderRequest, bool) {
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
		decoyReply := &commands.ReplicaDecoy{
			Cmds: commands.NewStorageReplicaCommands(c.geo, schemes.ByName(c.l.server.cfg.ReplicaNIKEScheme)),
		}
		return &senderRequest{
			ReplicaDecoy: decoyReply,
		}, true
	case *commands.ReplicaWrite:
		c.log.Debugf("Processing ReplicaWrite command for BoxID: %x", cmd.BoxID)
		trunnelWrite := pigeonhole.WireCommandToTrunnelReplicaWrite(cmd)
		resp := c.handleReplicaWrite(trunnelWrite)
		respWire := pigeonhole.TrunnelReplicaWriteReplyToWireCommand(resp, cmd.Cmds)
		c.log.Debugf("handleReplicaWrite returned: %T", respWire)
		return &senderRequest{
			ReplicaWriteReply: respWire,
		}, true
	case *commands.ReplicaMessage:
		c.log.Debugf("Processing ReplicaMessage command with ciphertext length: %d", len(cmd.Ciphertext))
		resp := c.handleReplicaMessage(cmd)
		c.log.Debugf("handleReplicaMessage returned: %T", resp)
		return &senderRequest{
			ReplicaMessageReply: resp,
		}, true
	default:
		c.log.Errorf("Received unexpected command type: %T", cmd)
		return nil, false
	}
	// not reached
}

func (c *incomingConn) countReplicas(doc *pki.Document) (int, error) {
	replicaKeys, err := replicaCommon.GetReplicaKeys(doc)
	if err != nil {
		return 0, err
	}
	return len(replicaKeys), nil
}

// replicaMessage's are sent from the courier to the replica storage servers
func (c *incomingConn) handleReplicaMessage(replicaMessage *commands.ReplicaMessage) *commands.ReplicaMessageReply {
	c.log.Debug("REPLICA_HANDLER: Starting handleReplicaMessage processing")
	nikeScheme := schemes.ByName(c.l.server.cfg.ReplicaNIKEScheme)
	scheme := mkem.NewScheme(nikeScheme)

	// Calculate envelope hash once and reuse it
	envelopeHash := replicaMessage.EnvelopeHash()

	// Construct the MKEM ciphertext from the ReplicaMessage fields
	// The Ciphertext field contains only the envelope, not the full CBOR-encoded mkem.Ciphertext
	ephemeralPublicKey, err := nikeScheme.UnmarshalBinaryPublicKey(replicaMessage.SenderEPubKey)
	if err != nil {
		c.log.Errorf("handleReplicaMessage failed to unmarshal SenderEPubKey: %s", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, envelopeHash, []byte{}, 0, false)
	}
	ct := &mkem.Ciphertext{
		EphemeralPublicKey: ephemeralPublicKey,
		DEKCiphertexts:     []*[mkem.DEKSize]byte{replicaMessage.DEK},
		Envelope:           replicaMessage.Ciphertext,
	}

	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	keypair, err := c.l.server.envelopeKeys.GetKeypair(replicaEpoch)
	if err != nil {
		c.log.Errorf("handleReplicaMessage envelopeKeys.GetKeypair failed: %s", err)
		return nil
	}
	c.log.Debug("Attempting to decapsulate message")
	requestRaw, err := scheme.Decapsulate(keypair.PrivateKey, ct)
	if err != nil {
		c.log.Errorf("handleReplicaMessage Decapsulate failed: %s", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, envelopeHash, []byte{}, 0, false)
	}

	c.log.Debug("Successfully decapsulated message, parsing command")
	msg, err := pigeonhole.ParseReplicaInnerMessage(requestRaw)
	if err != nil {
		c.log.Errorf("handleReplicaMessage failed to parse inner message: %s", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInvalidPayload, envelopeHash, []byte{}, 0, false)
	}
	c.log.Debug("Successfully parsed command")

	// Use the ephemeralPublicKey we already unmarshaled earlier
	senderpubkey := ephemeralPublicKey

	doc := c.l.server.PKIWorker.PKIDocument()
	if doc == nil {
		c.log.Error("handleReplicaMessage failed: no PKI document available")
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInvalidEpoch, envelopeHash, []byte{}, 0, false)
	}
	numReplicas, err := c.countReplicas(doc)
	if err != nil {
		c.log.Errorf("handleReplicaMessage failed to count replicas: %s", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, envelopeHash, []byte{}, 0, false)
	}
	replicaID, err := doc.GetReplicaIDByIdentityKey(c.l.server.identityPublicKey)
	if err != nil {
		c.log.Errorf("handleReplicaMessage failed to get our own replica ID: %s", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, envelopeHash, []byte{}, 0, false)
	}

	switch {
	case msg.ReadMsg != nil:
		myCmd := msg.ReadMsg
		c.log.Debugf("REPLICA_HANDLER: Processing decrypted ReplicaRead command for BoxID: %x", myCmd.BoxID)

		// Check if this replica is responsible for the BoxID using sharding
		shards, err := replicaCommon.GetShards(&myCmd.BoxID, doc)
		if err != nil {
			c.log.Errorf("handleReplicaMessage failed to get shards: %s", err)
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, envelopeHash, []byte{}, 0, false)
		}

		// Check if this replica is one of the shards for this BoxID
		myIdentityKey, err := c.l.server.identityPublicKey.MarshalBinary()
		if err != nil {
			c.log.Errorf("handleReplicaMessage failed to marshal identity key: %s", err)
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, envelopeHash, []byte{}, 0, false)
		}

		isShard := false
		for _, shard := range shards {
			if hmac.Equal(shard.IdentityKey, myIdentityKey) {
				isShard = true
				break
			}
		}

		if !isShard {
			if numReplicas >= 3 {
				// This replica is NOT responsible for the BoxID - proxy to the correct replica
				c.log.Debugf("REPLICA_HANDLER: This replica is NOT a shard for BoxID %x - PROXYING read request to appropriate shard", myCmd.BoxID)
				reply := c.proxyReadRequest(myCmd, senderpubkey, envelopeHash)
				c.log.Debugf("REPLICA_HANDLER: Successfully completed proxy read request for BoxID %x", myCmd.BoxID)
				return reply
			}
		}

		readReply := c.handleReplicaRead(myCmd)
		if readReply.ErrorCode != pigeonhole.ReplicaSuccess {
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, readReply.ErrorCode, envelopeHash, []byte{}, replicaID, true)
		}
		replyInnerMessage := pigeonhole.ReplicaMessageReplyInnerMessage{
			ReadReply: readReply,
		}
		replyInnerMessageBlob := replyInnerMessage.Bytes()
		envelopeReply := scheme.EnvelopeReply(keypair.PrivateKey, senderpubkey, replyInnerMessageBlob)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, readReply.ErrorCode, envelopeHash, envelopeReply.Envelope, replicaID, true)
	case msg.WriteMsg != nil:
		myCmd := msg.WriteMsg
		c.log.Debugf("Processing decrypted ReplicaWrite command for BoxID: %x", myCmd.BoxID)
		writeReply := c.handleReplicaWrite(myCmd)

		if numReplicas >= 3 {
			cmds := commands.NewStorageReplicaCommands(c.geo, nikeScheme)
			wireCmd := pigeonhole.TrunnelReplicaWriteToWireCommand(myCmd, cmds)
			c.l.server.connector.DispatchReplication(wireCmd)
		}

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
	resp, err := c.l.server.state.stateHandleReplicaRead(replicaRead)

	switch {
	case err == nil:
		// no error, success code path
		c.log.Debug("Replica read successful")
		reply := &pigeonhole.ReplicaReadReply{
			BoxID:      resp.BoxID,
			Signature:  resp.Signature,
			PayloadLen: uint32(len(resp.Payload)),
			Payload:    resp.Payload,
			ErrorCode:  pigeonhole.ReplicaSuccess,
		}
		return reply
	case errors.Is(err, ErrBoxIDNotFound):
		// handle Box ID not found error here
		// ThreeBitHacker says to emit a network message indicating sucess
		c.log.Error("Replica read failed, Box ID not found")
		reply := &pigeonhole.ReplicaReadReply{
			BoxID:      replicaRead.BoxID,
			PayloadLen: uint32(0),
			Payload:    nil,
			ErrorCode:  pigeonhole.ReplicaErrorBoxIDNotFound,
		}
		return reply
	case errors.Is(err, ErrFailedDBRead):
		// DB read has failed, handle it here
		c.log.Error("Replica read failed, DB read failed")
		errorCode := pigeonhole.ReplicaErrorDatabaseFailure
		reply := &pigeonhole.ReplicaReadReply{
			ErrorCode: errorCode,
		}
		return reply
	case errors.Is(err, ErrFailedToDeserialize):
		// handle failure to deserialize here
		c.log.Error("Replica read failed, failed to deserialize data from DB")
		errorCode := pigeonhole.ReplicaErrorDatabaseFailure
		reply := &pigeonhole.ReplicaReadReply{
			ErrorCode: errorCode,
		}
		return reply
	case errors.Is(err, ErrDBClosed):
		// this should never happen, probably a fatal error we cannot recover from
		c.log.Error("Replica read failed, DB is closed")
		errorCode := pigeonhole.ReplicaErrorDatabaseFailure
		reply := &pigeonhole.ReplicaReadReply{
			ErrorCode: errorCode,
		}
		return reply
	}

	// NOT reachable
	return nil
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
	wireWrite := pigeonhole.TrunnelReplicaWriteToWireCommand(replicaWrite, nil)
	err = c.l.server.state.handleReplicaWrite(wireWrite)
	if err != nil {
		c.log.Errorf("handleReplicaWrite state update failed: %v", err)
		return &pigeonhole.ReplicaWriteReply{
			ErrorCode: pigeonhole.ReplicaErrorDatabaseFailure,
		}
	}
	c.log.Debug("Replica write successful")
	return &pigeonhole.ReplicaWriteReply{
		ErrorCode: pigeonhole.ReplicaSuccess,
	}
}

// proxyReadRequest forwards a read request to the appropriate shard replica
// and returns the reply that should be sent back to the original client
func (c *incomingConn) proxyReadRequest(replicaRead *pigeonhole.ReplicaRead, originalSenderPubkey nike.PublicKey, originalEnvelopeHash *[32]byte) *commands.ReplicaMessageReply {
	// Input validation
	if replicaRead == nil {
		c.log.Error("PROXY_REQUEST: replicaRead is nil")
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, 0, false)
	}

	c.log.Debugf("PROXY_REQUEST: Starting proxy for BoxID: %x", replicaRead.BoxID)

	// Get PKI document
	doc := c.l.server.PKIWorker.PKIDocument()
	if doc == nil {
		c.log.Error("proxyReadRequest: no PKI document available")
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, 0, false)
	}

	// Get replica ID
	replicaID, err := doc.GetReplicaIDByIdentityKey(c.l.server.identityPublicKey)
	if err != nil {
		c.log.Errorf("proxyReadRequest: failed to get replica ID: %v", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, 0, false)
	}

	// Calculate shards for this BoxID
	shards, err := replicaCommon.GetShards(&replicaRead.BoxID, doc)
	if err != nil {
		c.log.Errorf("proxyReadRequest: failed to get shards: %v", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, 0, false)
	}

	// Validate: GetShards should ALWAYS return exactly 2 replicas (K=2)
	if len(shards) != 2 {
		c.log.Errorf("PROXY_REQUEST: BUG - GetShards returned %d replicas instead of 2 for BoxID %x", len(shards), replicaRead.BoxID[:8])
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, 0, false)
	}

	c.log.Debugf("PROXY_REQUEST: Shard replicas for BoxID %x: [%s, %s]", replicaRead.BoxID[:8], shards[0].Name, shards[1].Name)

	// Get our own identity key to find the other replica in this shard
	myIdentityKey, err := c.l.server.identityPublicKey.MarshalBinary()
	if err != nil {
		c.log.Errorf("proxyReadRequest: failed to marshal identity key: %v", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, 0, false)
	}

	// Find the other replica in this shard (the one that's not us)
	var otherReplica *pki.ReplicaDescriptor
	for _, shard := range shards {
		if !hmac.Equal(shard.IdentityKey, myIdentityKey) {
			otherReplica = shard
			break
		}
	}

	// Validate: After filtering self, should have exactly 1 other replica
	if otherReplica == nil {
		c.log.Errorf("PROXY_REQUEST: BUG - Could not find other replica in shard for BoxID %x (both replicas are self?)", replicaRead.BoxID[:8])
		return c.createReplicaMessageReply(
			c.l.server.cfg.ReplicaNIKEScheme,
			pigeonhole.ReplicaErrorInternalError,
			originalEnvelopeHash,
			[]byte{},
			0,
			false,
		)
	}

	c.log.Debugf("PROXY_REQUEST: Proxying read request to other replica in shard: %s", otherReplica.Name)

	// Use the other replica in this shard (no randomization needed since K=2)
	targetShard := otherReplica

	// Get current replica epoch and keypair
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	keypair, err := c.l.server.envelopeKeys.GetKeypair(replicaEpoch)
	if err != nil {
		c.log.Errorf("proxyReadRequest: failed to get keypair: %v", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, 0, false)
	}

	// Create MKEM scheme
	nikeScheme := schemes.ByName(c.l.server.cfg.ReplicaNIKEScheme)
	scheme := mkem.NewScheme(nikeScheme)

	// Create the inner message containing the read request
	innerMessage := pigeonhole.ReplicaInnerMessage{
		ReadMsg: replicaRead,
	}
	innerMessageBlob := innerMessage.Bytes()

	// Get the target replica's envelope public key (ONLY current epoch)
	targetEnvelopeKeyBytes, exists := targetShard.EnvelopeKeys[replicaEpoch]
	if !exists {
		c.log.Errorf("proxyReadRequest: no envelope key found for target replica %s at current epoch %d", targetShard.Name, replicaEpoch)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, 0, false)
	}

	targetEnvelopeKey, err := nikeScheme.UnmarshalBinaryPublicKey(targetEnvelopeKeyBytes)
	if err != nil {
		c.log.Errorf("proxyReadRequest: failed to unmarshal target envelope key: %v", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, 0, false)
	}

	c.log.Debugf("Using envelope key for target replica %s at current epoch %d", targetShard.Name, replicaEpoch)

	// Encapsulate the message for the target replica using MKEM
	mkemPrivateKey, envelope := scheme.Encapsulate([]nike.PublicKey{targetEnvelopeKey}, innerMessageBlob)

	// Create the ReplicaMessage command to send to target replica
	replicaMessage := &commands.ReplicaMessage{
		Cmds:               commands.NewStorageReplicaCommands(c.geo, nikeScheme),
		PigeonholeGeometry: nil,
		Scheme:             nikeScheme,
		SenderEPubKey:      envelope.EphemeralPublicKey.Bytes(),
		DEK:                envelope.DEKCiphertexts[0],
		Ciphertext:         envelope.Envelope,
	}

	// Calculate the target replica's identity hash for routing
	idHash := blake2b.Sum256(targetShard.IdentityKey)

	// Create a simple synchronous proxy implementation
	// This uses a direct connection approach rather than the async connector
	reply, err := c.sendProxyRequestSync(replicaMessage, &idHash, targetShard, mkemPrivateKey, targetEnvelopeKey, scheme)
	if err != nil {
		c.log.Errorf("Failed to send proxy request to %s: %v", targetShard.Name, err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorReplicationFailed, originalEnvelopeHash, []byte{}, replicaID, false)
	}

	// Process the reply and re-encrypt for the original client
	if reply == nil {
		c.log.Error("proxyReadRequest: received nil reply from target replica")
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, replicaID, false)
	}

	c.log.Debugf("Received proxy reply from %s with error code: %d", targetShard.Name, reply.ErrorCode)

	// Decrypt the envelope reply from the target replica
	if len(reply.EnvelopeReply) > 0 {
		decryptedReply, err := scheme.DecryptEnvelope(mkemPrivateKey, targetEnvelopeKey, reply.EnvelopeReply)
		if err != nil {
			c.log.Errorf("proxyReadRequest: failed to decrypt proxy reply envelope: %v", err)
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, replicaID, false)
		}

		// Parse the decrypted reply to get the actual read reply data
		replyInnerMessage, err := pigeonhole.ParseReplicaMessageReplyInnerMessage(decryptedReply)
		if err != nil {
			c.log.Errorf("proxyReadRequest: failed to parse proxy reply inner message: %v", err)
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, replicaID, false)
		}

		if replyInnerMessage.ReadReply == nil {
			c.log.Error("proxyReadRequest: proxy reply does not contain read reply")
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, replicaID, false)
		}

		// Now re-encrypt the read reply data for the original client
		newReplyInnerMessage := pigeonhole.ReplicaMessageReplyInnerMessage{
			ReadReply: replyInnerMessage.ReadReply,
		}
		newReplyInnerMessageBlob := newReplyInnerMessage.Bytes()
		envelopeReply := scheme.EnvelopeReply(keypair.PrivateKey, originalSenderPubkey, newReplyInnerMessageBlob)

		// Return the reply encrypted for the original client
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, replyInnerMessage.ReadReply.ErrorCode, originalEnvelopeHash, envelopeReply.Envelope, replicaID, true)
	}

	// No envelope reply data - just return the error code
	return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, reply.ErrorCode, originalEnvelopeHash, []byte{}, replicaID, true)
}

// sendProxyRequestSync sends a proxy request synchronously to the target replica
func (c *incomingConn) sendProxyRequestSync(replicaMessage *commands.ReplicaMessage, idHash *[32]byte, targetShard *pki.ReplicaDescriptor, mkemPrivateKey nike.PrivateKey, targetEnvelopeKey nike.PublicKey, scheme *mkem.Scheme) (*commands.ReplicaMessageReply, error) {
	// Register the proxy request with the proxy manager
	envelopeHash := *replicaMessage.EnvelopeHash()
	responseCh := c.l.server.proxyManager.RegisterProxyRequest(envelopeHash, mkemPrivateKey, targetEnvelopeKey, replicaMessage)

	// Dispatch the command to the target replica
	c.l.server.connector.DispatchCommand(replicaMessage, idHash)
	c.log.Debugf("Dispatched proxy request to %s, waiting for response", targetShard.Name)

	// Wait for the response with timeout
	timeout := 30 * time.Second
	select {
	case reply := <-responseCh:
		if reply == nil {
			return nil, fmt.Errorf("received nil reply from target replica")
		}
		c.log.Debugf("Received proxy reply from %s with error code: %d", targetShard.Name, reply.ErrorCode)
		return reply, nil

	case <-time.After(timeout):
		c.log.Errorf("Timeout waiting for proxy response from %s", targetShard.Name)
		return nil, fmt.Errorf("timeout waiting for proxy response")
	}
}
