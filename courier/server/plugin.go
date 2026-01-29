// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/pigeonhole"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

// CourierBookKeeping is used for:
// 1. deduping writes
// 2. deduping reads
// 3. caching replica replies
type CourierBookKeeping struct {
	Epoch                uint64
	QueryType            uint8
	IntermediateReplicas [2]uint8 // Store the replica IDs that were contacted
	EnvelopeReplies      [2]*commands.ReplicaMessageReply
}

// PendingReadRequest stores information about a read request waiting for immediate reply
type PendingReadRequest struct {
	RequestID uint64
	SURB      []byte
	Timeout   time.Time
}

// Courier handles the CBOR plugin interface for our courier service.
type Courier struct {
	write  func(cborplugin.Command)
	server *Server
	log    *logging.Logger

	cmds           *commands.Commands
	geo            *geo.Geometry
	envelopeScheme nike.Scheme
	pigeonholeGeo  *pigeonholeGeo.Geometry

	dedupCacheLock sync.RWMutex
	dedupCache     map[[hash.HashSize]byte]*CourierBookKeeping

	copyCacheLock sync.RWMutex
	copyCache     map[[hash.HashSize]byte]chan *commands.ReplicaMessageReply

	pendingRequestsLock sync.RWMutex
	pendingRequests     map[[hash.HashSize]byte]*PendingReadRequest
}

// NewCourier returns a new Courier type.
func NewCourier(s *Server, cmds *commands.Commands, scheme nike.Scheme) *Courier {
	pigeonholeGeo, err := pigeonholeGeo.NewGeometryFromSphinx(s.cfg.SphinxGeometry, scheme)
	if err != nil {
		panic(fmt.Sprintf("Failed to create pigeonhole geometry: %v", err))
	}

	courier := &Courier{
		server:          s,
		log:             s.logBackend.GetLogger("courier"),
		cmds:            cmds,
		geo:             s.cfg.SphinxGeometry,
		envelopeScheme:  scheme,
		pigeonholeGeo:   pigeonholeGeo,
		dedupCache:      make(map[[hash.HashSize]byte]*CourierBookKeeping),
		copyCache:       make(map[[hash.HashSize]byte]chan *commands.ReplicaMessageReply),
		pendingRequests: make(map[[hash.HashSize]byte]*PendingReadRequest),
	}
	return courier
}

// StartPlugin starts the CBOR plugin service which listens for socket connections
// from the service node.
func (s *Server) StartPlugin() {
	socketFile := filepath.Join(s.cfg.DataDir, fmt.Sprintf("%d.courier.socket", os.Getpid()))

	scheme := schemes.ByName(s.cfg.EnvelopeScheme)
	cmds := commands.NewStorageReplicaCommands(s.cfg.SphinxGeometry, scheme)

	courier := NewCourier(s, cmds, scheme)
	s.Courier = courier

	// Force a PKI refresh on startup to ensure we have current documents
	// even if there were previous fetch failures
	go func() {
		time.Sleep(2 * time.Second) // Give the PKI worker time to start
		if err := s.PKI.ForceFetchPKI(); err != nil {
			s.log.Warningf("Failed to force fetch PKI on startup: %v", err)
		} else {
			s.log.Debugf("Successfully force fetched PKI on startup")
		}
	}()

	server := cborplugin.NewServer(s.LogBackend().GetLogger("courier_plugin"), socketFile, new(cborplugin.RequestFactory), courier)
	fmt.Printf("%s\n", socketFile)
	server.Accept()
	server.Wait()
	err := os.Remove(socketFile)
	if err != nil {
		panic(err)
	}

}

func (e *Courier) HandleReply(reply *commands.ReplicaMessageReply) {
	isCopy := false
	e.copyCacheLock.RLock()
	if _, ok := e.copyCache[*reply.EnvelopeHash]; ok {
		isCopy = true
	}
	e.copyCacheLock.RUnlock()

	if isCopy {
		panic("NOT YET IMPLEMENTED")
	}
	e.CacheReply(reply)
}

func (e *Courier) CacheReply(reply *commands.ReplicaMessageReply) {
	e.log.Debugf("CacheReply called with envelope hash: %x", reply.EnvelopeHash)

	if !e.validateReply(reply) {
		e.log.Errorf("courier/!e.validateReply(reply:%v)", reply)
		return
	}

	// Check for pending read request and immediately proxy reply if found
	if reply.IsRead {
		if e.tryImmediateReplyProxy(reply) {
			e.log.Debugf("Immediately proxied reply for envelope hash: %x", reply.EnvelopeHash)
			// Still cache the reply for potential future requests
		}
	}

	e.dedupCacheLock.Lock()
	defer e.dedupCacheLock.Unlock()

	entry, ok := e.dedupCache[*reply.EnvelopeHash]
	if ok {
		e.handleExistingEntry(entry, reply)
		e.logFinalCacheState(reply)
	} else {
		e.log.Errorf("Courier received reply with unknown envelope hash; %x", *reply.EnvelopeHash)
	}
}

// validateReply checks if the reply should be cached
func (e *Courier) validateReply(reply *commands.ReplicaMessageReply) bool {
	if reply.EnvelopeHash == nil {
		e.log.Debugf("CacheReply: envelope hash is nil, not caching")
		return false
	}

	if reply.ErrorCode != pigeonhole.ReplicaSuccess {
		e.log.Debugf("CacheReply: reply has error code %d, not caching", reply.ErrorCode)
		return false
	}

	e.log.Debug("CacheReply: caching reply")

	return true
}

// handleExistingEntry processes replies for existing cache entries
func (e *Courier) handleExistingEntry(entry *CourierBookKeeping, reply *commands.ReplicaMessageReply) {
	e.log.Debugf("CacheReply: found existing cache entry for envelope hash %x", reply.EnvelopeHash)

	replyIndex := e.findReplicaIndex(entry, reply.ReplicaID)
	if replyIndex >= 0 {
		e.storeReplyIfEmpty(entry, reply, replyIndex)
	} else {
		// Check if we can accommodate this replica in an unused slot (marked as 255)
		for i, id := range entry.IntermediateReplicas {
			if id == 255 && entry.EnvelopeReplies[i] == nil {
				e.log.Debugf("CacheReply: storing reply from replica %d in unused slot %d", reply.ReplicaID, i)
				entry.IntermediateReplicas[i] = reply.ReplicaID
				entry.EnvelopeReplies[i] = reply
				return
			}
		}
		e.log.Warningf("CacheReply: replica ID %d not found in IntermediateReplicas %v and no unused slots available for envelope hash %x", reply.ReplicaID, entry.IntermediateReplicas, reply.EnvelopeHash)
	}
}

// findReplicaIndex finds the index for a replica ID in IntermediateReplicas
func (e *Courier) findReplicaIndex(entry *CourierBookKeeping, replicaID uint8) int {
	for i, id := range entry.IntermediateReplicas {
		if id == replicaID {
			return i
		}
	}
	return -1
}

// storeReplyIfEmpty stores the reply only if the slot is empty, or if we're replacing an error with success
func (e *Courier) storeReplyIfEmpty(entry *CourierBookKeeping, reply *commands.ReplicaMessageReply, replyIndex int) {
	existingReply := entry.EnvelopeReplies[replyIndex]

	if existingReply == nil {
		e.log.Infof("CacheReply: storing reply from replica %d at IntermediateReplicas index %d", reply.ReplicaID, replyIndex)
		entry.EnvelopeReplies[replyIndex] = reply
	} else if existingReply.ErrorCode != 0 && reply.ErrorCode == 0 {
		// Overwrite cached error with successful response
		e.log.Infof("CacheReply: overwriting cached error (code %d) with successful reply from replica %d at index %d",
			existingReply.ErrorCode, reply.ReplicaID, replyIndex)
		entry.EnvelopeReplies[replyIndex] = reply
	} else {
		e.log.Infof("CacheReply: reply from replica %d already cached (error=%d), ignoring duplicate (error=%d)",
			reply.ReplicaID, existingReply.ErrorCode, reply.ErrorCode)
	}
}

// createNewEntry creates a new cache entry for unknown envelope hashes
func (e *Courier) createNewEntry(reply *commands.ReplicaMessageReply) {
	e.log.Infof("CacheReply: received reply for unknown EnvelopeHash %x, creating new cache entry", reply.EnvelopeHash)

	// For read replies to unknown envelope hashes, we don't know which replicas were
	// originally selected by the sharding algorithm, so we can't create a proper cache entry.
	// However, we can try to accommodate the reply by creating a flexible entry.
	currentEpoch := e.getCurrentEpoch()

	// Create a cache entry that accommodates this replica ID in the correct slot
	// Use replica ID to determine which slot to use: replica 0 → slot 0, replica 1 → slot 1
	var intermediateReplicas [2]uint8
	var replyIndex int

	if reply.ReplicaID == 0 {
		intermediateReplicas = [2]uint8{0, 255} // replica 0 in slot 0, slot 1 unknown
		replyIndex = 0
	} else {
		intermediateReplicas = [2]uint8{255, reply.ReplicaID} // slot 0 unknown, replica in slot 1
		replyIndex = 1
	}

	newEntry := &CourierBookKeeping{
		Epoch:                currentEpoch,
		IntermediateReplicas: intermediateReplicas,
		EnvelopeReplies:      [2]*commands.ReplicaMessageReply{nil, nil},
	}

	// Store the reply in the correct slot based on replica ID
	e.log.Debugf("CacheReply: creating new cache entry and storing reply from replica %d at index %d", reply.ReplicaID, replyIndex)
	newEntry.EnvelopeReplies[replyIndex] = reply

	e.dedupCache[*reply.EnvelopeHash] = newEntry
}

// getCurrentEpoch gets the current epoch from PKI document
func (e *Courier) getCurrentEpoch() uint64 {
	if pkiDoc := e.server.PKI.PKIDocument(); pkiDoc != nil {
		return pkiDoc.Epoch
	}
	return 0
}

// logFinalCacheState logs the final state of the cache entry
func (e *Courier) logFinalCacheState(reply *commands.ReplicaMessageReply) {
	finalEntry := e.dedupCache[*reply.EnvelopeHash]
	reply0Available := finalEntry.EnvelopeReplies[0] != nil
	reply1Available := finalEntry.EnvelopeReplies[1] != nil
	e.log.Debugf("CacheReply: final cache state for %x - Reply[0]: %v, Reply[1]: %v", reply.EnvelopeHash, reply0Available, reply1Available)
}

// tryImmediateReplyProxy checks if there's a pending read request and immediately proxies the reply
func (e *Courier) tryImmediateReplyProxy(reply *commands.ReplicaMessageReply) bool {
	e.log.Debugf("tryImmediateReplyProxy: Checking for pending read request for envelope hash %x", reply.EnvelopeHash)

	// Skip proxying if the reply has an error code or empty payload
	// The client will timeout and retry, no need to waste mixnet bandwidth
	if reply.ErrorCode != pigeonhole.ReplicaSuccess {
		e.log.Debugf("tryImmediateReplyProxy: Skipping proxy for error reply (ErrorCode=%d) for envelope hash %x",
			reply.ErrorCode, reply.EnvelopeHash)
		return false
	}

	if len(reply.EnvelopeReply) == 0 {
		e.log.Debugf("tryImmediateReplyProxy: Skipping proxy for empty reply for envelope hash %x", reply.EnvelopeHash)
		return false
	}

	e.pendingRequestsLock.Lock()
	defer e.pendingRequestsLock.Unlock()

	pendingRequest, exists := e.pendingRequests[*reply.EnvelopeHash]
	if !exists {
		e.log.Debugf("tryImmediateReplyProxy: No pending read request found for envelope hash %x", reply.EnvelopeHash)
		return false
	}

	e.log.Debugf("tryImmediateReplyProxy: Found pending read request for envelope hash %x", reply.EnvelopeHash)

	// Check if the request has timed out
	if time.Now().After(pendingRequest.Timeout) {
		e.log.Debugf("Pending read request for envelope hash %x has timed out, removing", reply.EnvelopeHash)
		delete(e.pendingRequests, *reply.EnvelopeHash)
		return false
	}

	// Remove the pending request since we're about to fulfill it
	delete(e.pendingRequests, *reply.EnvelopeHash)

	e.log.Debugf("tryImmediateReplyProxy: Sending immediate reply for envelope hash %x", reply.EnvelopeHash)

	// Send the immediate reply
	go func() {
		// Find the correct reply index by looking up the replica's position in IntermediateReplicas
		var replyIndex uint8 = 255 // Default to invalid index

		// Get the cache entry to find the IntermediateReplicas array
		e.dedupCacheLock.RLock()
		cacheEntry, exists := e.dedupCache[*reply.EnvelopeHash]
		e.dedupCacheLock.RUnlock()

		if exists && cacheEntry != nil {
			// Find the replica's position in the IntermediateReplicas array
			for i, replicaID := range cacheEntry.IntermediateReplicas {
				if replicaID == reply.ReplicaID {
					replyIndex = uint8(i)
					break
				}
			}
		}

		// If we couldn't find the replica in the cache, fall back to the old logic
		// This shouldn't happen in normal operation but provides a safety net
		if replyIndex == 255 {
			e.log.Warningf("Could not find replica %d in IntermediateReplicas, falling back to default mapping", reply.ReplicaID)
			if reply.ReplicaID == 0 {
				replyIndex = 0
			} else {
				replyIndex = 1
			}
		}

		// Create proper CourierQueryReply with the replica's response
		// Determine reply type based on whether this is a read operation
		// For reads: return ReplyTypePayload (contains encrypted message data)
		// For writes: return ReplyTypeACK (acknowledgment only)
		var replyType uint8
		if reply.IsRead {
			replyType = pigeonhole.ReplyTypePayload // Read operation - has encrypted message data
			e.log.Debugf("tryImmediateReplyProxy: setting ReplyType:=ReplyTypePayload (read operation) with %d bytes of encrypted data",
				len(reply.EnvelopeReply))
		} else {
			replyType = pigeonhole.ReplyTypeACK // Write operation - just acknowledgment
			e.log.Debugf("tryImmediateReplyProxy: setting ReplyType:=ReplyTypeACK (write operation)")
		}

		courierReply := &pigeonhole.CourierQueryReply{
			ReplyType: 0, // 0 = envelope_reply
			EnvelopeReply: &pigeonhole.CourierEnvelopeReply{
				EnvelopeHash: *reply.EnvelopeHash,
				ReplyIndex:   replyIndex, // Use the correct reply index, not replica ID
				ReplyType:    replyType,
				PayloadLen:   uint32(len(reply.EnvelopeReply)),
				Payload:      reply.EnvelopeReply,
				ErrorCode:    pigeonhole.EnvelopeErrorSuccess,
			},
		}

		e.log.Errorf("tryImmediateReplyProxy: Sending response with %d bytes of ciphertext, replyIndex=%d, ReplyType=%d EnvHash=%v",
			len(reply.EnvelopeReply), replyIndex, replyType, *reply.EnvelopeHash)

		e.write(&cborplugin.Response{
			ID:      pendingRequest.RequestID,
			SURB:    pendingRequest.SURB,
			Payload: courierReply.Bytes(),
		})
	}()

	return true
}

// storePendingRequest stores a pending request with a timeout
func (e *Courier) storePendingRequest(envHash *[hash.HashSize]byte, requestID uint64, surb []byte) {
	e.pendingRequestsLock.Lock()
	defer e.pendingRequestsLock.Unlock()

	// Set timeout to allow for replica response delays
	seconds := 20
	timeout := time.Now().Add(time.Duration(seconds) * time.Second)

	e.pendingRequests[*envHash] = &PendingReadRequest{
		RequestID: requestID,
		SURB:      surb,
		Timeout:   timeout,
	}

	e.log.Debugf("Stored pending read request for envelope hash %x with %d-second timeout", envHash, seconds)

	// Start a goroutine to clean up expired requests
	go e.cleanupExpiredRequest(envHash, timeout)
}

// cleanupExpiredRequest removes a pending request after its timeout expires
func (e *Courier) cleanupExpiredRequest(envHash *[hash.HashSize]byte, timeout time.Time) {
	// Wait until the timeout expires
	time.Sleep(time.Until(timeout))

	e.pendingRequestsLock.Lock()
	defer e.pendingRequestsLock.Unlock()

	// Check if the request is still there and has expired
	if pendingRequest, exists := e.pendingRequests[*envHash]; exists && time.Now().After(pendingRequest.Timeout) {
		delete(e.pendingRequests, *envHash)
		e.log.Debugf("Cleaned up expired pending read request for envelope hash %x", envHash)
	}
}

func (e *Courier) propagateQueryToReplicas(courierMessage *pigeonhole.CourierEnvelope) error {
	e.log.Debugf("handleCourierEnvelope: Starting to handle envelope with intermediate replicas [%d, %d]",
		courierMessage.IntermediateReplicas[0], courierMessage.IntermediateReplicas[1])

	firstReplicaID := courierMessage.IntermediateReplicas[0]
	e.log.Debugf("handleCourierEnvelope: Preparing message for first replica ID %d", firstReplicaID)
	replicaMsg1 := &commands.ReplicaMessage{
		Cmds:               e.cmds,
		PigeonholeGeometry: e.pigeonholeGeo,
		Scheme:             e.envelopeScheme,

		SenderEPubKey: courierMessage.SenderPubkey,
		DEK:           &courierMessage.Dek1,
		Ciphertext:    courierMessage.Ciphertext,
	}
	e.log.Debugf("handleCourierEnvelope: Sending message to first replica ID %d", firstReplicaID)
	if err := e.server.SendMessage(firstReplicaID, replicaMsg1); err != nil {
		e.log.Errorf("handleCourierEnvelope: Failed to send message to first replica %d: %s", firstReplicaID, err)
		return fmt.Errorf("failed to dispatch to replica %d: %w", firstReplicaID, err)
	}

	secondReplicaID := courierMessage.IntermediateReplicas[1]
	e.log.Debugf("handleCourierEnvelope: Preparing message for second replica ID %d", secondReplicaID)
	replicaMsg2 := &commands.ReplicaMessage{
		Cmds:               e.cmds,
		PigeonholeGeometry: e.pigeonholeGeo,
		Scheme:             e.envelopeScheme,

		SenderEPubKey: courierMessage.SenderPubkey,
		DEK:           &courierMessage.Dek2,
		Ciphertext:    courierMessage.Ciphertext,
	}
	e.log.Debugf("handleCourierEnvelope: Sending message to second replica ID %d", secondReplicaID)
	if err := e.server.SendMessage(secondReplicaID, replicaMsg2); err != nil {
		e.log.Errorf("handleCourierEnvelope: Failed to send message to second replica %d: %s", secondReplicaID, err)
		return fmt.Errorf("failed to dispatch to replica %d: %w", secondReplicaID, err)
	}

	e.log.Debugf("handleCourierEnvelope: Successfully dispatched messages to both replicas")
	return nil
}

// handleNewMessage processes new messages and dispatches them to replicas.
func (e *Courier) handleNewMessage(envHash *[hash.HashSize]byte, courierMessage *pigeonhole.CourierEnvelope) *pigeonhole.CourierQueryReply {
	e.log.Debugf("handleNewMessage: Processing new message for envelope hash %x", envHash)

	if err := e.propagateQueryToReplicas(courierMessage); err != nil {
		e.log.Errorf("handleNewMessage: Failed to handle courier envelope: %s", err)
		e.log.Debugf("handleNewMessage: Returning error reply due to internal error")
		return e.createEnvelopeErrorReply(envHash, pigeonhole.EnvelopeErrorPropagationError, courierMessage.ReplyIndex)
	}

	e.log.Debugf("handleNewMessage: Successfully dispatched to replicas, waiting for replica responses (no immediate reply)")
	return nil
}

func (e *Courier) handleOldMessage(cacheEntry *CourierBookKeeping, envHash *[hash.HashSize]byte, courierMessage *pigeonhole.CourierEnvelope) *pigeonhole.CourierQueryReply {
	e.log.Debugf("handleOldMessage called for envelope hash: %x, requested ReplyIndex: %d", envHash, courierMessage.ReplyIndex)

	// Check if cacheEntry is nil before accessing its fields
	if cacheEntry == nil {
		e.log.Debugf("Cache entry is nil, no replies available")
		return e.createEnvelopeErrorReply(envHash, pigeonhole.EnvelopeErrorCacheCorruption, courierMessage.ReplyIndex)
	}

	// Log cache state
	reply0Available := cacheEntry.EnvelopeReplies[0] != nil
	reply1Available := cacheEntry.EnvelopeReplies[1] != nil
	e.log.Debugf("Cache state - Reply[0]: %v, Reply[1]: %v envHash:%v", reply0Available, reply1Available, envHash)

	var payload []byte
	var isRead bool

	if cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex] != nil {
		entry := cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex]
		payload = entry.EnvelopeReply
		isRead = entry.IsRead
		e.log.Debugf("Found reply [len:%d err:%d read:%v] at requested index %d for %v", len(payload), entry.ErrorCode, entry.IsRead, courierMessage.ReplyIndex, envHash)
		if len(payload) == 0 && cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex^1] != nil {
			oentry := cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex^1]
			e.log.Debugf("entry at idx %v is empty; other: [len:%d err:%d read:%v]", courierMessage.ReplyIndex, len(oentry.EnvelopeReply), oentry.ErrorCode, oentry.IsRead)
		}
	} else {
		e.log.Debugf("No reply available at requested index %d", courierMessage.ReplyIndex)
		if cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex^1] != nil {
			courierMessage.ReplyIndex = courierMessage.ReplyIndex ^ 1
			entry := cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex]
			payload = entry.EnvelopeReply
			isRead = entry.IsRead
			e.log.Debugf("But there is a reply for %d, so returning that (envHash:%v)", courierMessage.ReplyIndex, envHash)
		} else {
			payload = nil // Return empty payload but keep the requested ReplyIndex
			isRead = false
		}
	}

	// Determine reply type based on whether this is a read operation
	// For reads: return ReplyTypePayload (contains encrypted message data)
	// For writes: return ReplyTypeACK (acknowledgment only)
	var replyType uint8
	if isRead {
		replyType = pigeonhole.ReplyTypePayload // Read operation - has encrypted message data
	} else {
		replyType = pigeonhole.ReplyTypeACK // Write operation - just acknowledgment
	}

	reply := &pigeonhole.CourierQueryReply{
		ReplyType: 0, // 0 = envelope_reply
		EnvelopeReply: &pigeonhole.CourierEnvelopeReply{
			EnvelopeHash: *envHash,
			ReplyIndex:   courierMessage.ReplyIndex,
			ReplyType:    replyType,
			PayloadLen:   uint32(len(payload)),
			Payload:      payload,
			ErrorCode:    pigeonhole.EnvelopeErrorSuccess,
		},
	}

	e.log.Debugf("handleOldMessage returning payload length: %d, ReplyType=%d", len(payload), replyType)
	return reply
}

// OnCommand is only called when we receive queries from the client via the mixnet
func (e *Courier) OnCommand(cmd cborplugin.Command) error {
	var request *cborplugin.Request
	switch r := cmd.(type) {
	case *cborplugin.Request:
		request = r
	default:
		return errors.New("bug in courier-plugin: received invalid Command type")
	}

	courierQuery, err := pigeonhole.CourierQueryFromBytes(request.Payload)
	if err != nil {
		return errors.New("CBOR decoding failed")
	}

	// Handle CourierEnvelope if present
	if courierQuery.Envelope != nil {
		reply := e.cacheHandleCourierEnvelope(courierQuery.QueryType, courierQuery.Envelope, request.ID, request.SURB)

		go func() {
			// send reply
			e.write(&cborplugin.Response{
				ID:      request.ID,
				SURB:    request.SURB,
				Payload: reply.Bytes(),
			})
		}()
	}

	return nil
}

func (e *Courier) cacheHandleCourierEnvelope(queryType uint8, courierMessage *pigeonhole.CourierEnvelope, requestID uint64, surb []byte) *pigeonhole.CourierQueryReply {
	envHash := courierMessage.EnvelopeHash()

	e.dedupCacheLock.RLock()
	cacheEntry, ok := e.dedupCache[*envHash]
	e.dedupCacheLock.RUnlock()

	switch {
	case ok:
		e.log.Debugf("OnCommand: Found cached entry for envelope hash %x, calling handleOldMessage", envHash)
		return e.handleOldMessage(cacheEntry, envHash, courierMessage)
	case !ok:
		e.log.Errorf("OnCommand: No cached entry for envelope hash %x, calling handleNewMessage", envHash)
		e.storePendingRequest(envHash, requestID, surb)
		e.dedupCacheLock.Lock()
		currentEpoch := e.getCurrentEpoch()
		e.dedupCache[*envHash] = &CourierBookKeeping{
			Epoch:                currentEpoch,
			QueryType:            queryType,
			IntermediateReplicas: courierMessage.IntermediateReplicas,
			EnvelopeReplies:      [2]*commands.ReplicaMessageReply{nil, nil},
		}
		e.dedupCacheLock.Unlock()

		return e.handleNewMessage(envHash, courierMessage)
	}

	// not reached
	return nil
}

// Copy command functions have been removed as requested

// createEnvelopeErrorReply creates a CourierEnvelopeReply with the specified error code
func (e *Courier) createEnvelopeErrorReply(envHash *[hash.HashSize]byte, errorCode uint8, replyIndex uint8) *pigeonhole.CourierQueryReply {
	e.log.Errorf("Envelope operation failed with error code %d", errorCode)
	return &pigeonhole.CourierQueryReply{
		ReplyType: 0, // 0 = envelope_reply
		EnvelopeReply: &pigeonhole.CourierEnvelopeReply{
			EnvelopeHash: *envHash,
			ReplyIndex:   replyIndex,
			ReplyType:    pigeonhole.ReplyTypeACK, // Use ACK type for error replies (errors during dispatch)
			PayloadLen:   0,
			Payload:      nil,
			ErrorCode:    errorCode, // Use the actual error code
		},
	}
}

func (e *Courier) RegisterConsumer(s *cborplugin.Server) {
	e.write = s.Write
}

func (e *Courier) SetWriteFunc(writeFunc func(cborplugin.Command)) {
	e.write = writeFunc
}
