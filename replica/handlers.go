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
	"github.com/katzenpost/katzenpost/replica/instrument"
)

// createReplicaMessageReply creates a ReplicaMessageReply with proper PigeonholeGeometry
func (c *incomingConn) createReplicaMessageReply(nikeScheme string, errorCode uint8, envelopeHash *[32]byte, envelopeReply []byte, replicaID uint8) *commands.ReplicaMessageReply {
	scheme := schemes.ByName(nikeScheme)

	return &commands.ReplicaMessageReply{
		Cmds:               commands.NewStorageReplicaCommands(c.geo, scheme),
		PigeonholeGeometry: c.l.server.pigeonholeGeo,
		ErrorCode:          errorCode,
		EnvelopeHash:       envelopeHash,
		EnvelopeReply:      envelopeReply,
		ReplicaID:          replicaID,
	}
}

func (c *incomingConn) onReplicaCommand(rawCmd commands.Command, emitter *delayedReplyEmitter) (*senderRequest, bool) {
	if _, isDecoy := rawCmd.(*commands.ReplicaDecoy); !isDecoy {
		c.log.Debugf("onReplicaCommand received command type: %T with value: %+v", rawCmd, rawCmd)
	}
	switch cmd := rawCmd.(type) {
	case *commands.NoOp:
		c.log.Debug("Received NoOp from peer")
		return nil, true
	case *commands.Disconnect:
		c.log.Debug("Received disconnect from peer")
		return nil, false
	case *commands.ReplicaDecoy:
		instrument.IncomingDecoysReceived()
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
		// Handle asynchronously so proxy requests don't block the
		// command loop. Semaphore limits active handlers.
		recvAt := time.Now()
		c.l.server.Add(1)
		go func() {
			defer c.l.server.Done()
			select {
			case <-c.l.closeAllCh:
				c.log.Debugf("Terminating gracefully.")
				return
			default:
			}
			select {
			case c.l.server.proxySema <- struct{}{}:
			case <-c.l.closeAllCh:
				c.log.Debugf("Terminating gracefully.")
				return
			}
			defer func() { <-c.l.server.proxySema }()
			resp := c.handleReplicaMessage(cmd)
			c.log.Debugf("handleReplicaMessage returned: %T", resp)
			select {
			case <-c.l.closeAllCh:
				c.log.Debugf("Terminating gracefully.")
				return
			default:
			}
			emitter.Enqueue(&senderRequest{ReplicaMessageReply: resp, recvAt: recvAt})
		}()
		return nil, true
	default:
		// A staggered fleet means a newer peer may legitimately send
		// command types this build does not handle yet. Tolerate them:
		// tearing the session down would orphan every in-flight reply.
		c.warnUnknownCommandOnce(cmd)
		return nil, true
	}
	// not reached
}

// warnUnknownCommandOnce logs an unhandled-but-decodable command type once
// per type for this connection. Only called from the command loop goroutine.
func (c *incomingConn) warnUnknownCommandOnce(cmd commands.Command) {
	name := fmt.Sprintf("%T", cmd)
	if c.unknownCmdSeen == nil {
		c.unknownCmdSeen = make(map[string]bool)
	}
	if !c.unknownCmdSeen[name] {
		c.unknownCmdSeen[name] = true
		c.log.Warningf("Ignoring unhandled command type %s from peer (newer peer?)", name)
	}
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
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, envelopeHash, []byte{}, 0)
	}
	ct := &mkem.Ciphertext{
		EphemeralPublicKey: ephemeralPublicKey,
		DEKCiphertexts:     [][]byte{replicaMessage.DEK[:]},
		Envelope:           replicaMessage.Ciphertext,
	}

	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	// Try each envelope keypair in the replica's tolerance window
	// {current-1, current, current+1}. This matches the courier's
	// CourierEnvelope.Epoch validation: whatever epoch the courier
	// decided to forward, we try the corresponding private key here.
	// Missing keys (e.g. next-epoch key not yet generated) are skipped.
	requestRaw, keypair, successEpoch, err := tryDecapsulateAcrossEpochWindow(c.l.server.envelopeKeys, scheme, ct, replicaEpoch)
	if err != nil {
		c.log.Errorf("handleReplicaMessage decapsulation failed across epoch window (current=%d): %s", replicaEpoch, err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInvalidEpoch, envelopeHash, []byte{}, 0)
	}
	if successEpoch != replicaEpoch {
		c.log.Debugf("handleReplicaMessage decapsulated with non-current epoch key: replica_epoch=%d decap_epoch=%d",
			replicaEpoch, successEpoch)
	}
	innerBytes, err := pigeonhole.ExtractMessageFromPaddedPayload(requestRaw)
	if err != nil {
		c.log.Errorf("handleReplicaMessage failed to extract padded inner message: %s", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInvalidPayload, envelopeHash, []byte{}, 0)
	}
	msg, err := pigeonhole.ParseReplicaInnerMessage(innerBytes)
	if err != nil {
		c.log.Errorf("handleReplicaMessage failed to parse inner message: %s", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInvalidPayload, envelopeHash, []byte{}, 0)
	}

	// Use the ephemeralPublicKey we already unmarshaled earlier
	senderpubkey := ephemeralPublicKey

	doc := c.l.server.PKIWorker.LastCachedPKIDocument()
	if doc == nil {
		c.log.Error("handleReplicaMessage failed: no PKI document available")
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInvalidEpoch, envelopeHash, []byte{}, 0)
	}
	replicaID, err := doc.GetReplicaIDByIdentityKey(c.l.server.identityPublicKey)
	if err != nil {
		c.log.Errorf("handleReplicaMessage failed to get our own replica ID: %s", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, envelopeHash, []byte{}, 0)
	}

	switch {
	case msg.ReadMsg != nil:
		myCmd := msg.ReadMsg
		c.log.Debugf("REPLICA_HANDLER: Processing decrypted ReplicaRead command for BoxID: %x", myCmd.BoxID)

		// Check if this replica is in the shard for this BoxID
		// Only shard members should read locally - intermediate replicas must proxy
		shards, err := replicaCommon.GetShards(&myCmd.BoxID, doc)
		if err != nil {
			c.log.Errorf("handleReplicaMessage read failed to get shards: %s", err)
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, envelopeHash, []byte{}, 0)
		}

		if len(shards) == 0 {
			c.log.Errorf("handleReplicaMessage read failed, zero shards available for BoxID: %x", myCmd.BoxID)
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, envelopeHash, []byte{}, 0)
		}

		myIdentityKey, err := c.l.server.identityPublicKey.MarshalBinary()
		if err != nil {
			c.log.Errorf("handleReplicaMessage read failed to marshal identity key: %s", err)
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, envelopeHash, []byte{}, 0)
		}

		isShard := false
		for _, shard := range shards {
			if hmac.Equal(shard.IdentityKey, myIdentityKey) {
				isShard = true
				break
			}
		}

		if isShard {
			// This replica is in the shard - read locally
			c.log.Debugf("REPLICA_HANDLER: This replica IS a shard for BoxID %x - reading locally", myCmd.BoxID)
			readReply := c.handleReplicaRead(myCmd)
			// Always encrypt the reply (success or error) so the client can decrypt and see the error code
			replyInnerMessage := pigeonhole.ReplicaMessageReplyInnerMessage{
				ReadReply: readReply,
			}
			// Pad read reply so tombstone reads are indistinguishable from normal reads
			replyInnerMessageBlob, err := pigeonhole.PadReplyInnerMessageForEncryption(&replyInnerMessage, c.l.server.pigeonholeGeo)
			if err != nil {
				c.log.Errorf("REPLICA_HANDLER: failed to pad read reply: %s", err)
				return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, envelopeHash, []byte{}, replicaID)
			}
			envelopeReply := scheme.EnvelopeReply(keypair.PrivateKey, senderpubkey, replyInnerMessageBlob)
			if readReply.ErrorCode == pigeonhole.ReplicaSuccess {
				c.log.Debugf("REPLICA_HANDLER: Found data locally for BoxID %x", myCmd.BoxID)
			} else {
				c.log.Debugf("REPLICA_HANDLER: This replica IS a shard for BoxID %x but data not found locally (error code: %d)", myCmd.BoxID, readReply.ErrorCode)
			}
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, readReply.ErrorCode, envelopeHash, envelopeReply.Envelope, replicaID)
		}

		// This replica is NOT in the shard - proxy to the correct replica
		c.log.Debugf("REPLICA_HANDLER: This replica is NOT a shard for BoxID %x - PROXYING read request to appropriate shard", myCmd.BoxID)
		reply := c.proxyReadRequest(myCmd, senderpubkey, envelopeHash)
		c.log.Debugf("REPLICA_HANDLER: Successfully completed proxy read request for BoxID %x", myCmd.BoxID)
		return reply
	case msg.WriteMsg != nil:
		myCmd := msg.WriteMsg
		c.log.Debugf("Processing decrypted ReplicaWrite command for BoxID: %x", myCmd.BoxID)

		// Check if this replica is in the shard for this BoxID
		// Intermediate replicas must NOT write locally - only shard members store data
		shards, err := replicaCommon.GetShards(&myCmd.BoxID, doc)
		if err != nil {
			c.log.Errorf("handleReplicaMessage write failed to get shards: %s", err)
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, envelopeHash, []byte{}, 0)
		}

		myIdentityKey, err := c.l.server.identityPublicKey.MarshalBinary()
		if err != nil {
			c.log.Errorf("handleReplicaMessage write failed to marshal identity key: %s", err)
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, envelopeHash, []byte{}, 0)
		}

		isShard := false
		for _, shard := range shards {
			if hmac.Equal(shard.IdentityKey, myIdentityKey) {
				isShard = true
				break
			}
		}

		if isShard {
			// This replica is in the shard - write locally
			c.log.Debugf("REPLICA_HANDLER: This replica IS a shard for BoxID %x - writing locally", myCmd.BoxID)
			writeReply := c.handleReplicaWrite(myCmd)

			// If write succeeded, trigger replication to other K-1 shard replicas
			// This is the only place replication is triggered (from intermediary level)
			// to avoid infinite loops between shard replicas
			if writeReply.ErrorCode == pigeonhole.ReplicaSuccess {
				wireWrite := pigeonhole.TrunnelReplicaWriteToWireCommand(myCmd, nil)
				c.log.Debugf("REPLICA_HANDLER: Dispatching replication for BoxID %x to other shards", myCmd.BoxID)
				c.l.server.connector.DispatchReplication(wireWrite)
			}

			replyInnerMessage := pigeonhole.ReplicaMessageReplyInnerMessage{
				MessageType: 1,
				WriteReply:  writeReply,
			}
			// Pad write reply so writes are indistinguishable from reads
			replyInnerMessageBlob, err := pigeonhole.PadReplyInnerMessageForEncryption(&replyInnerMessage, c.l.server.pigeonholeGeo)
			if err != nil {
				c.log.Errorf("REPLICA_HANDLER: failed to pad write reply: %s", err)
				return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, envelopeHash, []byte{}, replicaID)
			}
			envelopeReply := scheme.EnvelopeReply(keypair.PrivateKey, senderpubkey, replyInnerMessageBlob)
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, writeReply.ErrorCode, envelopeHash, envelopeReply.Envelope, replicaID)
		}

		// This replica is NOT in the shard - proxy the write to a shard replica
		// The receiving shard will handle replication to other K-1 shards
		c.log.Debugf("REPLICA_HANDLER: This replica is NOT a shard for BoxID %x - proxying write to shard", myCmd.BoxID)
		return c.proxyWriteRequest(myCmd, senderpubkey, envelopeHash)
	default:
		c.log.Error("BUG: handleReplicaMessage failed: invalid request was decrypted")
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, envelopeHash, []byte{}, 0)
	}
}

func (c *incomingConn) handleReplicaRead(replicaRead *pigeonhole.ReplicaRead) *pigeonhole.ReplicaReadReply {
	c.log.Debugf("Handling replica read request for BoxID: %x", replicaRead.BoxID)
	resp, err := c.l.server.state.stateHandleReplicaRead(replicaRead)

	switch {
	case err == nil:
		if len(resp.Payload) == 0 {
			// Tombstone: box exists but payload was intentionally deleted
			c.log.Debugf("Replica read found tombstone for BoxID: %x", replicaRead.BoxID)
			return &pigeonhole.ReplicaReadReply{
				BoxID:     resp.BoxID,
				Signature: resp.Signature,
				ErrorCode: pigeonhole.ReplicaErrorTombstone,
			}
		}
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

	// Check if this is a tombstone (empty payload)
	isTombstone := replicaWrite.PayloadLen == 0 || len(replicaWrite.Payload) == 0

	var reply *pigeonhole.ReplicaWriteReply
	if isTombstone {
		reply = c.handleTombstone(replicaWrite)
	} else {
		// Validate payload size against geometry limits.
		// The payload is BACAP ciphertext, which must be exactly the expected size.
		expectedCiphertextSize := c.l.server.pigeonholeGeo.CalculateBoxCiphertextLength()
		if len(replicaWrite.Payload) != expectedCiphertextSize {
			c.log.Errorf("handleReplicaWrite invalid payload size: got %d bytes, expected exactly %d bytes",
				len(replicaWrite.Payload), expectedCiphertextSize)
			return &pigeonhole.ReplicaWriteReply{
				ErrorCode: pigeonhole.ReplicaErrorInvalidPayload,
			}
		}

		// Normal write path
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
		// Convert trunnel type to wire command for state handling.
		// state.handleReplicaWrite performs the check-and-put atomically
		// under a per-BoxID lock; no pre-check is needed here.
		wireWrite := pigeonhole.TrunnelReplicaWriteToWireCommand(replicaWrite, nil)
		err = c.l.server.state.handleReplicaWrite(wireWrite)
		if err != nil {
			// Check if this is the "already exists" case - this is expected during replication
			if errors.Is(err, ErrBoxAlreadyExists) {
				c.log.Debugf("handleReplicaWrite: BoxID already exists (idempotent write)")
				return &pigeonhole.ReplicaWriteReply{
					ErrorCode: pigeonhole.ReplicaErrorBoxAlreadyExists,
				}
			}
			if errors.Is(err, ErrStorageFull) {
				c.log.Warningf("handleReplicaWrite: rejected, storage full")
				return &pigeonhole.ReplicaWriteReply{
					ErrorCode: pigeonhole.ReplicaErrorStorageFull,
				}
			}
			c.log.Errorf("handleReplicaWrite state update failed: %v", err)
			return &pigeonhole.ReplicaWriteReply{
				ErrorCode: pigeonhole.ReplicaErrorDatabaseFailure,
			}
		}
		c.log.Debug("Replica write successful")
		reply = &pigeonhole.ReplicaWriteReply{
			ErrorCode: pigeonhole.ReplicaSuccess,
		}
	}
	return reply
}

// handleTombstone processes a tombstone message, which is a BACAP message with
// an empty payload used to delete previously stored messages. This selectively
// breaks unlinkability guarantees to allow users to delete messages after sending them.
func (c *incomingConn) handleTombstone(replicaWrite *pigeonhole.ReplicaWrite) *pigeonhole.ReplicaWriteReply {
	c.log.Debugf("Processing tombstone for BoxID: %x", replicaWrite.BoxID)

	// Verify the signature against an empty payload
	s := ed25519.Scheme()
	verifyKey, err := s.UnmarshalBinaryPublicKey(replicaWrite.BoxID[:])
	if err != nil {
		c.log.Errorf("handleTombstone failed to unmarshal BoxID as public key: %v", err)
		return &pigeonhole.ReplicaWriteReply{
			ErrorCode: pigeonhole.ReplicaErrorInvalidBoxID,
		}
	}

	if !s.Verify(verifyKey, []byte{}, replicaWrite.Signature[:], nil) {
		c.log.Error("handleTombstone signature verification failed")
		return &pigeonhole.ReplicaWriteReply{
			ErrorCode: pigeonhole.ReplicaErrorInvalidSignature,
		}
	}

	// Store the tombstone (empty payload with signature) in the database
	err = c.l.server.state.handleReplicaTombstone(replicaWrite.BoxID, replicaWrite.Signature)
	if err != nil {
		c.log.Errorf("handleTombstone storage failed: %v", err)
		return &pigeonhole.ReplicaWriteReply{
			ErrorCode: pigeonhole.ReplicaErrorDatabaseFailure,
		}
	}

	c.log.Debugf("Tombstone processed successfully for BoxID: %x", replicaWrite.BoxID)
	return &pigeonhole.ReplicaWriteReply{
		ErrorCode: pigeonhole.ReplicaSuccess,
	}
}

// proxyShardOrder returns the shard holders reordered so the randomly
// chosen candidate leads and the remaining holders follow as failover
// targets, preserving their relative order.
func proxyShardOrder(shards []*pki.ReplicaDescriptor, first int) []*pki.ReplicaDescriptor {
	ordered := make([]*pki.ReplicaDescriptor, 0, len(shards))
	ordered = append(ordered, shards[first])
	for i, s := range shards {
		if i != first {
			ordered = append(ordered, s)
		}
	}
	return ordered
}

// proxyToShard encapsulates the padded inner message for one shard
// holder and dispatches it synchronously, returning the raw reply
// together with the MKEM keys needed to decrypt it.
func (c *incomingConn) proxyToShard(targetShard *pki.ReplicaDescriptor, replicaEpoch uint64, innerMessageBlob []byte, scheme *mkem.Scheme, nikeScheme nike.Scheme) (*commands.ReplicaMessageReply, nike.PrivateKey, nike.PublicKey, error) {
	targetEnvelopeKeyBytes, exists := targetShard.EnvelopeKeys[replicaEpoch]
	if !exists {
		return nil, nil, nil, fmt.Errorf("no envelope key for %s at replica epoch %d", targetShard.Name, replicaEpoch)
	}
	targetEnvelopeKey, err := nikeScheme.UnmarshalBinaryPublicKey(targetEnvelopeKeyBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unmarshal envelope key for %s: %v", targetShard.Name, err)
	}
	mkemPrivateKey, envelope := scheme.Encapsulate([]nike.PublicKey{targetEnvelopeKey}, innerMessageBlob)
	replicaMessage := &commands.ReplicaMessage{
		Cmds:               commands.NewStorageReplicaCommands(c.geo, nikeScheme),
		PigeonholeGeometry: nil,
		Scheme:             nikeScheme,
		SenderEPubKey:      envelope.EphemeralPublicKey.Bytes(),
		DEK:                (*[mkem.DEKSize]byte)(envelope.DEKCiphertexts[0]),
		Ciphertext:         envelope.Envelope,
	}
	idHash := blake2b.Sum256(targetShard.IdentityKey)
	reply, err := c.sendProxyRequestSync(replicaMessage, &idHash, targetShard, mkemPrivateKey, targetEnvelopeKey, scheme)
	if err != nil {
		return nil, nil, nil, err
	}
	if reply == nil {
		return nil, nil, nil, errors.New("nil reply from target replica")
	}
	return reply, mkemPrivateKey, targetEnvelopeKey, nil
}

// proxyReadRequest forwards a read request to the appropriate shard replica
// and returns the reply that should be sent back to the original client
func (c *incomingConn) proxyReadRequest(replicaRead *pigeonhole.ReplicaRead, originalSenderPubkey nike.PublicKey, originalEnvelopeHash *[32]byte) *commands.ReplicaMessageReply {
	// Input validation
	if replicaRead == nil {
		c.log.Error("PROXY_REQUEST: replicaRead is nil")
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, 0)
	}

	c.log.Debugf("PROXY_REQUEST: Starting proxy for BoxID: %x", replicaRead.BoxID)

	// Get PKI document
	doc := c.l.server.PKIWorker.LastCachedPKIDocument()
	if doc == nil {
		c.log.Error("proxyReadRequest: no PKI document available")
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, 0)
	}

	// Get replica ID
	replicaID, err := doc.GetReplicaIDByIdentityKey(c.l.server.identityPublicKey)
	if err != nil {
		c.log.Errorf("proxyReadRequest: failed to get replica ID: %v", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, 0)
	}

	// Calculate shards for this BoxID
	shards, err := replicaCommon.GetShards(&replicaRead.BoxID, doc)
	if err != nil {
		c.log.Errorf("proxyReadRequest: failed to get shards: %v", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, 0)
	}

	// Select a random shard using hpqc's cryptographic Reader —
	// unbiased, goroutine-safe, no per-call Rand construction.
	idx, err := pigeonhole.CryptoRandIndex(len(shards))
	if err != nil {
		c.log.Errorf("proxyReadRequest: CryptoRandIndex failed: %v", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, 0)
	}
	// Get current replica epoch and keypair
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	keypair, err := c.l.server.envelopeKeys.GetKeypair(replicaEpoch)
	if err != nil {
		c.log.Errorf("proxyReadRequest: failed to get keypair: %v", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, 0)
	}

	// Create MKEM scheme
	nikeScheme := schemes.ByName(c.l.server.cfg.ReplicaNIKEScheme)
	scheme := mkem.NewScheme(nikeScheme)

	// Create the inner message containing the read request, then length-
	// prefix-and-pad so the peer replica's ExtractMessageFromPaddedPayload
	// recovers the exact bytes after MKEM decryption.
	innerMessage := pigeonhole.ReplicaInnerMessage{
		ReadMsg: replicaRead,
	}
	innerMessageBlob, err := pigeonhole.PadInnerMessageForEncryption(&innerMessage, c.l.server.pigeonholeGeo)
	if err != nil {
		c.log.Errorf("proxyReadRequest: failed to pad inner message: %v", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, 0)
	}

	// Try the randomly chosen holder first, then fail over to the other
	// holder(s): one sick shard replica must degrade to its live peer,
	// not into a client-visible error.
	var (
		reply             *commands.ReplicaMessageReply
		mkemPrivateKey    nike.PrivateKey
		targetEnvelopeKey nike.PublicKey
		targetShard       *pki.ReplicaDescriptor
	)
	for _, candidate := range proxyShardOrder(shards, idx) {
		reply, mkemPrivateKey, targetEnvelopeKey, err = c.proxyToShard(candidate, replicaEpoch, innerMessageBlob, scheme, nikeScheme)
		if err == nil {
			targetShard = candidate
			break
		}
		c.log.Errorf("proxyReadRequest: proxy to %s failed: %v", candidate.Name, err)
	}
	if reply == nil {
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorReplicationFailed, originalEnvelopeHash, []byte{}, replicaID)
	}

	c.log.Debugf("Received proxy reply from %s with error code: %d", targetShard.Name, reply.ErrorCode)

	// Decrypt the envelope reply from the target replica
	if len(reply.EnvelopeReply) > 0 {
		decryptedReply, err := scheme.DecryptEnvelope(mkemPrivateKey, targetEnvelopeKey, reply.EnvelopeReply)
		if err != nil {
			c.log.Errorf("proxyReadRequest: failed to decrypt proxy reply envelope: %v", err)
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, replicaID)
		}

		// Parse the decrypted reply to get the actual read reply data
		replyBytes, err := pigeonhole.ExtractMessageFromPaddedPayload(decryptedReply)
		if err != nil {
			c.log.Errorf("proxyReadRequest: failed to extract padded reply inner message: %v", err)
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, replicaID)
		}
		replyInnerMessage, err := pigeonhole.ParseReplicaMessageReplyInnerMessage(replyBytes)
		if err != nil {
			c.log.Errorf("proxyReadRequest: failed to parse proxy reply inner message: %v", err)
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, replicaID)
		}

		if replyInnerMessage.ReadReply == nil {
			c.log.Error("proxyReadRequest: proxy reply does not contain read reply")
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, replicaID)
		}

		// Now re-encrypt the read reply data for the original client
		// Pad so tombstone reads are indistinguishable from normal reads
		newReplyInnerMessage := pigeonhole.ReplicaMessageReplyInnerMessage{
			ReadReply: replyInnerMessage.ReadReply,
		}
		newReplyInnerMessageBlob, err := pigeonhole.PadReplyInnerMessageForEncryption(&newReplyInnerMessage, c.l.server.pigeonholeGeo)
		if err != nil {
			c.log.Errorf("proxyReadRequest: failed to pad read reply: %s", err)
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, replicaID)
		}
		envelopeReply := scheme.EnvelopeReply(keypair.PrivateKey, originalSenderPubkey, newReplyInnerMessageBlob)

		// Return the reply encrypted for the original client
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, replyInnerMessage.ReadReply.ErrorCode, originalEnvelopeHash, envelopeReply.Envelope, replicaID)
	}

	// No envelope reply data - just return the error code
	return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, reply.ErrorCode, originalEnvelopeHash, []byte{}, replicaID)
}

// proxyWriteRequest forwards a write request to the appropriate shard replica
// and returns the reply that should be sent back to the original client.
// This is used when an intermediate replica receives a write for a BoxID
// that it doesn't shard - it proxies to a shard replica to get the actual result.
func (c *incomingConn) proxyWriteRequest(replicaWrite *pigeonhole.ReplicaWrite, originalSenderPubkey nike.PublicKey, originalEnvelopeHash *[32]byte) *commands.ReplicaMessageReply {
	// Input validation
	if replicaWrite == nil {
		c.log.Error("proxyWriteRequest: replicaWrite is nil")
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, 0)
	}

	c.log.Debugf("proxyWriteRequest: Starting proxy for BoxID: %x", replicaWrite.BoxID)

	// Get PKI document
	doc := c.l.server.PKIWorker.LastCachedPKIDocument()
	if doc == nil {
		c.log.Error("proxyWriteRequest: no PKI document available")
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, 0)
	}

	// Get replica ID
	replicaID, err := doc.GetReplicaIDByIdentityKey(c.l.server.identityPublicKey)
	if err != nil {
		c.log.Errorf("proxyWriteRequest: failed to get replica ID: %v", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, 0)
	}

	// Calculate shards for this BoxID
	shards, err := replicaCommon.GetShards(&replicaWrite.BoxID, doc)
	if err != nil {
		c.log.Errorf("proxyWriteRequest: failed to get shards: %v", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, 0)
	}

	// Select a random shard using hpqc's cryptographic Reader —
	// unbiased, goroutine-safe, no per-call Rand construction.
	idx, err := pigeonhole.CryptoRandIndex(len(shards))
	if err != nil {
		c.log.Errorf("proxyWriteRequest: CryptoRandIndex failed: %v", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, 0)
	}
	// Get current replica epoch and keypair
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	keypair, err := c.l.server.envelopeKeys.GetKeypair(replicaEpoch)
	if err != nil {
		c.log.Errorf("proxyWriteRequest: failed to get keypair: %v", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, 0)
	}

	// Create MKEM scheme
	nikeScheme := schemes.ByName(c.l.server.cfg.ReplicaNIKEScheme)
	scheme := mkem.NewScheme(nikeScheme)

	// Create the inner message containing the write request, then length-
	// prefix-and-pad so the peer replica's ExtractMessageFromPaddedPayload
	// recovers the exact bytes after MKEM decryption.
	innerMessage := pigeonhole.ReplicaInnerMessage{
		MessageType: 1, // 1 = write
		WriteMsg:    replicaWrite,
	}
	innerMessageBlob, err := pigeonhole.PadInnerMessageForEncryption(&innerMessage, c.l.server.pigeonholeGeo)
	if err != nil {
		c.log.Errorf("proxyWriteRequest: failed to pad inner message: %v", err)
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, 0)
	}

	// Try the randomly chosen holder first, then fail over to the other
	// holder(s): one sick shard replica must degrade to its live peer,
	// not into a client-visible error.
	var (
		reply             *commands.ReplicaMessageReply
		mkemPrivateKey    nike.PrivateKey
		targetEnvelopeKey nike.PublicKey
		targetShard       *pki.ReplicaDescriptor
	)
	for _, candidate := range proxyShardOrder(shards, idx) {
		reply, mkemPrivateKey, targetEnvelopeKey, err = c.proxyToShard(candidate, replicaEpoch, innerMessageBlob, scheme, nikeScheme)
		if err == nil {
			targetShard = candidate
			break
		}
		c.log.Errorf("proxyWriteRequest: proxy to %s failed: %v", candidate.Name, err)
	}
	if reply == nil {
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorReplicationFailed, originalEnvelopeHash, []byte{}, replicaID)
	}

	c.log.Debugf("proxyWriteRequest: Received proxy reply from %s with error code: %d", targetShard.Name, reply.ErrorCode)

	// Decrypt the envelope reply from the target replica
	if len(reply.EnvelopeReply) > 0 {
		decryptedReply, err := scheme.DecryptEnvelope(mkemPrivateKey, targetEnvelopeKey, reply.EnvelopeReply)
		if err != nil {
			c.log.Errorf("proxyWriteRequest: failed to decrypt proxy reply envelope: %v", err)
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, replicaID)
		}

		// Parse the decrypted reply to get the actual write reply data
		replyBytes, err := pigeonhole.ExtractMessageFromPaddedPayload(decryptedReply)
		if err != nil {
			c.log.Errorf("proxyWriteRequest: failed to extract padded reply inner message: %v", err)
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, replicaID)
		}
		replyInnerMessage, err := pigeonhole.ParseReplicaMessageReplyInnerMessage(replyBytes)
		if err != nil {
			c.log.Errorf("proxyWriteRequest: failed to parse proxy reply inner message: %v", err)
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, replicaID)
		}

		if replyInnerMessage.WriteReply == nil {
			c.log.Error("proxyWriteRequest: proxy reply does not contain write reply")
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, replicaID)
		}

		// Now re-encrypt the write reply data for the original client
		// Pad so write replies are indistinguishable from read replies
		newReplyInnerMessage := pigeonhole.ReplicaMessageReplyInnerMessage{
			MessageType: 1,
			WriteReply:  replyInnerMessage.WriteReply,
		}
		newReplyInnerMessageBlob, err := pigeonhole.PadReplyInnerMessageForEncryption(&newReplyInnerMessage, c.l.server.pigeonholeGeo)
		if err != nil {
			c.log.Errorf("proxyWriteRequest: failed to pad write reply: %s", err)
			return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, pigeonhole.ReplicaErrorInternalError, originalEnvelopeHash, []byte{}, replicaID)
		}
		envelopeReply := scheme.EnvelopeReply(keypair.PrivateKey, originalSenderPubkey, newReplyInnerMessageBlob)

		// Return the reply encrypted for the original client
		return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, replyInnerMessage.WriteReply.ErrorCode, originalEnvelopeHash, envelopeReply.Envelope, replicaID)
	}

	// No envelope reply data - just return the error code
	return c.createReplicaMessageReply(c.l.server.cfg.ReplicaNIKEScheme, reply.ErrorCode, originalEnvelopeHash, []byte{}, replicaID)
}

// sendProxyRequestSync sends a proxy request synchronously to the target replica
func (c *incomingConn) sendProxyRequestSync(replicaMessage *commands.ReplicaMessage, idHash *[32]byte, targetShard *pki.ReplicaDescriptor, mkemPrivateKey nike.PrivateKey, targetEnvelopeKey nike.PublicKey, scheme *mkem.Scheme) (*commands.ReplicaMessageReply, error) {
	// Register the proxy request with the proxy manager
	envelopeHash := *replicaMessage.EnvelopeHash()
	responseCh := c.l.server.proxyManager.RegisterProxyRequest(envelopeHash, mkemPrivateKey, targetEnvelopeKey, replicaMessage)

	// Dispatch the command to the target replica
	c.l.server.connector.DispatchCommand(replicaMessage, idHash)
	c.log.Debugf("Dispatched proxy request to %s, waiting for response", targetShard.Name)

	// Wait for the response with configurable timeout
	timeout := time.Duration(c.l.server.cfg.ProxyRequestTimeout) * time.Second
	select {
	case <-c.l.closeAllCh:
		return nil, fmt.Errorf("shutting down")
	default:
	}
	select {
	case reply := <-responseCh:
		if reply == nil {
			return nil, fmt.Errorf("received nil reply from target replica")
		}
		c.log.Debugf("Received proxy reply from %s with error code: %d", targetShard.Name, reply.ErrorCode)
		return reply, nil
	case <-time.After(timeout):
		c.log.Errorf("Timeout waiting for proxy response from %s after %v", targetShard.Name, timeout)
		return nil, fmt.Errorf("timeout waiting for proxy response")
	case <-c.l.closeAllCh:
		return nil, fmt.Errorf("shutting down")
	}
}
