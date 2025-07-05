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

// Error message constants
var (
	errInvalidDestinationID = errors.New("invalid destination ID")
	errConnectionNotFound   = errors.New("connection not found")
	errNilEnvelopeHash      = errors.New("envelope hash is nil")
	errNilDEKElements       = errors.New("DEK array contains nil elements")
	errCBORDecodingFailed   = errors.New("CBOR decoding failed")
)

// CourierEnvelope operation error codes - using centralized error codes
const (
	envelopeErrorNilDEKElements  = pigeonhole.EnvelopeErrorNilDEKElements
	envelopeErrorCacheCorruption = pigeonhole.EnvelopeErrorCacheCorruption
	envelopeErrorInternalError   = pigeonhole.EnvelopeErrorInternalError
)

// envelopeErrorToString returns a human-readable string for envelope error codes
func envelopeErrorToString(errorCode uint8) string {
	return pigeonhole.EnvelopeErrorToString(errorCode)
}

// CourierBookKeeping is used for:
// 1. deduping writes
// 2. deduping reads
// 3. caching replica replies
type CourierBookKeeping struct {
	Epoch                uint64
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
		//e.handleCopyReply(reply)
		return
	}
	e.CacheReply(reply)
}

func (e *Courier) CacheReply(reply *commands.ReplicaMessageReply) {
	e.log.Debugf("CacheReply called with envelope hash: %x", reply.EnvelopeHash)

	if !e.validateReply(reply) {
		return
	}

	// Check for pending read request and immediately proxy reply if found
	if e.tryImmediateReplyProxy(reply) {
		e.log.Debugf("Immediately proxied reply for envelope hash: %x", reply.EnvelopeHash)
		// Still cache the reply for potential future requests
	}

	e.dedupCacheLock.Lock()
	defer e.dedupCacheLock.Unlock()

	entry, ok := e.dedupCache[*reply.EnvelopeHash]
	if ok {
		e.handleExistingEntry(entry, reply)
	} else {
		e.createNewEntry(reply)
	}

	e.logFinalCacheState(reply)
}

// validateReply checks if the reply should be cached
func (e *Courier) validateReply(reply *commands.ReplicaMessageReply) bool {
	if !reply.IsRead {
		e.log.Debug("CacheReply: not caching write reply")
		return false
	}

	e.log.Debug("CacheReply: caching read reply")

	if reply.EnvelopeHash == nil {
		e.log.Debugf("CacheReply: envelope hash is nil, not caching - error: %s", errNilEnvelopeHash)
		return false
	}

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

// storeReplyIfEmpty stores the reply only if the slot is empty
func (e *Courier) storeReplyIfEmpty(entry *CourierBookKeeping, reply *commands.ReplicaMessageReply, replyIndex int) {
	if entry.EnvelopeReplies[replyIndex] == nil {
		e.log.Debugf("CacheReply: storing reply from replica %d at IntermediateReplicas index %d", reply.ReplicaID, replyIndex)
		entry.EnvelopeReplies[replyIndex] = reply
	} else {
		e.log.Debugf("CacheReply: reply from replica %d already cached, ignoring duplicate", reply.ReplicaID)
	}
}

// createNewEntry creates a new cache entry for unknown envelope hashes
func (e *Courier) createNewEntry(reply *commands.ReplicaMessageReply) {
	e.log.Debugf("CacheReply: received reply for unknown EnvelopeHash %x, creating new cache entry", reply.EnvelopeHash)

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
		// Map replica ID to correct reply index (replica 0 → index 0, others → index 1)
		var replyIndex uint8
		if reply.ReplicaID == 0 {
			replyIndex = 0
		} else {
			replyIndex = 1
		}

		// Create proper CourierQueryReply with the replica's response
		courierReply := &pigeonhole.CourierQueryReply{
			ReplyType: 0, // 0 = envelope_reply
			EnvelopeReply: &pigeonhole.CourierEnvelopeReply{
				EnvelopeHash: *reply.EnvelopeHash,
				ReplyIndex:   replyIndex, // Use the correct reply index, not replica ID
				PayloadLen:   uint32(len(reply.EnvelopeReply)),
				Payload:      reply.EnvelopeReply,
				ErrorCode:    0,
			},
		}

		e.log.Debugf("tryImmediateReplyProxy: Sending response with %d bytes of ciphertext, replyIndex=%d", len(reply.EnvelopeReply), replyIndex)

		e.write(&cborplugin.Response{
			ID:      pendingRequest.RequestID,
			SURB:    pendingRequest.SURB,
			Payload: courierReply.Bytes(),
		})
	}()

	return true
}

// storePendingRequest stores a pending request with a 30-second timeout
func (e *Courier) storePendingRequest(envHash *[hash.HashSize]byte, requestID uint64, surb []byte) {
	e.pendingRequestsLock.Lock()
	defer e.pendingRequestsLock.Unlock()

	// Set 30-second timeout to allow for replica response delays
	timeout := time.Now().Add(30 * time.Second)

	e.pendingRequests[*envHash] = &PendingReadRequest{
		RequestID: requestID,
		SURB:      surb,
		Timeout:   timeout,
	}

	e.log.Debugf("Stored pending read request for envelope hash %x with 30-second timeout", envHash)

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

func (e *Courier) handleCourierEnvelope(courierMessage *pigeonhole.CourierEnvelope) error {
	replicas := make([]*commands.ReplicaMessage, 2)

	firstReplicaID := courierMessage.IntermediateReplicas[0]
	replicas[0] = &commands.ReplicaMessage{
		Cmds:               e.cmds,
		PigeonholeGeometry: e.pigeonholeGeo,
		Scheme:             e.envelopeScheme,

		SenderEPubKey: courierMessage.SenderPubkey,
		DEK:           &courierMessage.Dek1,
		Ciphertext:    courierMessage.Ciphertext,
	}
	e.server.SendMessage(firstReplicaID, replicas[0])

	secondReplicaID := courierMessage.IntermediateReplicas[1]
	replicas[1] = &commands.ReplicaMessage{
		Cmds:               e.cmds,
		PigeonholeGeometry: e.pigeonholeGeo,
		Scheme:             e.envelopeScheme,

		SenderEPubKey: courierMessage.SenderPubkey,
		DEK:           &courierMessage.Dek2,
		Ciphertext:    courierMessage.Ciphertext,
	}
	e.server.SendMessage(secondReplicaID, replicas[1])
	return nil
}

func (e *Courier) handleNewMessage(envHash *[hash.HashSize]byte, courierMessage *pigeonhole.CourierEnvelope) *pigeonhole.CourierQueryReply {
	if err := e.handleCourierEnvelope(courierMessage); err != nil {
		e.log.Errorf("Failed to handle courier envelope: %s", err)
		if err == errNilDEKElements {
			return e.createEnvelopeErrorReply(envHash, envelopeErrorNilDEKElements, courierMessage.ReplyIndex)
		}
		return e.createEnvelopeErrorReply(envHash, envelopeErrorInternalError, courierMessage.ReplyIndex)
	}

	reply := &pigeonhole.CourierQueryReply{
		ReplyType: 0, // 0 = envelope_reply
		EnvelopeReply: &pigeonhole.CourierEnvelopeReply{
			EnvelopeHash: *envHash,
			ReplyIndex:   courierMessage.ReplyIndex,
			PayloadLen:   0,
			Payload:      nil,
			ErrorCode:    1, // Error code for timeout
		},
	}
	return reply
}

func (e *Courier) handleOldMessage(cacheEntry *CourierBookKeeping, envHash *[hash.HashSize]byte, courierMessage *pigeonhole.CourierEnvelope) *pigeonhole.CourierQueryReply {
	e.log.Debugf("handleOldMessage called for envelope hash: %x, requested ReplyIndex: %d", envHash, courierMessage.ReplyIndex)

	// Check if cacheEntry is nil before accessing its fields
	if cacheEntry == nil {
		e.log.Debugf("Cache entry is nil, no replies available")
		return e.createEnvelopeErrorReply(envHash, envelopeErrorCacheCorruption, courierMessage.ReplyIndex)
	}

	// Log cache state
	reply0Available := cacheEntry.EnvelopeReplies[0] != nil
	reply1Available := cacheEntry.EnvelopeReplies[1] != nil
	e.log.Debugf("Cache state - Reply[0]: %v, Reply[1]: %v", reply0Available, reply1Available)

	var payload []byte
	replyIndex := courierMessage.ReplyIndex

	if cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex] != nil {
		e.log.Debugf("Found reply at requested index %d", courierMessage.ReplyIndex)
		payload = cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex].EnvelopeReply
	} else if cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex^1] != nil {
		e.log.Debugf("No reply at requested index %d, checking alternate index %d", courierMessage.ReplyIndex, courierMessage.ReplyIndex^1)
		payload = cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex^1].EnvelopeReply
		replyIndex = courierMessage.ReplyIndex ^ 1
	} else {
		e.log.Debugf("No replies available in cache")
		payload = nil
	}

	reply := &pigeonhole.CourierQueryReply{
		ReplyType: 0, // 0 = envelope_reply
		EnvelopeReply: &pigeonhole.CourierEnvelopeReply{
			EnvelopeHash: *envHash,
			ReplyIndex:   replyIndex,
			PayloadLen:   uint32(len(payload)),
			Payload:      payload,
			ErrorCode:    0,
		},
	}

	e.log.Debugf("handleOldMessage returning payload length: %d", len(payload))
	return reply
}

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
		// Provide detailed size information for debugging
		expectedWriteSize := e.pigeonholeGeo.CourierQueryWriteLength
		expectedReadSize := e.pigeonholeGeo.CourierQueryReadLength
		actualSize := len(request.Payload)

		e.log.Debugf("Failed to decode CourierQuery trunnel blob: %s (received %d bytes, expected %d for write or %d for read)",
			err, actualSize, expectedWriteSize, expectedReadSize)

		// Since parsing failed, we can't access the envelope hash or reply index
		// Create a generic error response with zero values
		var zeroHash [32]byte
		errorReply := &pigeonhole.CourierQueryReply{
			ReplyType: 0, // 0 = envelope_reply
			EnvelopeReply: &pigeonhole.CourierEnvelopeReply{
				EnvelopeHash: zeroHash,
				ReplyIndex:   0, // Default to 0 since we can't determine the intended ReplyIndex
				PayloadLen:   0,
				Payload:      nil,
				ErrorCode:    1, // Error code for parsing failure
			},
		}
		go func() {
			e.write(&cborplugin.Response{
				ID:      request.ID,
				SURB:    request.SURB,
				Payload: errorReply.Bytes(),
			})
		}()
		return errCBORDecodingFailed
	}

	// Handle CourierEnvelope if present
	if courierQuery.Envelope != nil {
		reply := e.cacheHandleCourierEnvelope(courierQuery.Envelope, request.ID, request.SURB)

		go func() {
			// send reply
			e.write(&cborplugin.Response{
				ID:      request.ID,
				SURB:    request.SURB,
				Payload: reply.Bytes(),
			})
		}()
	}

	// Copy command handling has been removed as requested

	return nil
}

func (e *Courier) cacheHandleCourierEnvelope(courierMessage *pigeonhole.CourierEnvelope, requestID uint64, surb []byte) *pigeonhole.CourierQueryReply {
	// Compute envelope hash using the new helper method
	// This ensures consistency between courier and replica envelope hash calculations
	envHash := courierMessage.EnvelopeHash()

	e.dedupCacheLock.RLock()
	cacheEntry, ok := e.dedupCache[*envHash]
	e.dedupCacheLock.RUnlock()

	if ok {
		e.log.Debugf("OnCommand: Found cached entry for envelope hash %x, calling handleOldMessage", envHash)
		return e.handleOldMessage(cacheEntry, envHash, courierMessage)
	}

	e.log.Debugf("OnCommand: No cached entry for envelope hash %x, calling handleNewMessage", envHash)

	e.storePendingRequest(envHash, requestID, surb)

	e.dedupCacheLock.Lock()

	// Get current epoch, defaulting to 0 if PKI document is not available yet
	var currentEpoch uint64
	if pkiDoc := e.server.PKI.PKIDocument(); pkiDoc != nil {
		currentEpoch = pkiDoc.Epoch
	}

	e.dedupCache[*envHash] = &CourierBookKeeping{
		Epoch:                currentEpoch,
		IntermediateReplicas: courierMessage.IntermediateReplicas,
		EnvelopeReplies:      [2]*commands.ReplicaMessageReply{nil, nil},
	}
	e.dedupCacheLock.Unlock()
	return e.handleNewMessage(envHash, courierMessage)
}

// Copy command functions have been removed as requested

// createEnvelopeErrorReply creates a CourierEnvelopeReply with the specified error code
func (e *Courier) createEnvelopeErrorReply(envHash *[hash.HashSize]byte, errorCode uint8, replyIndex uint8) *pigeonhole.CourierQueryReply {
	e.log.Debugf("Envelope operation failed with error code %d: %s", errorCode, envelopeErrorToString(errorCode))
	return &pigeonhole.CourierQueryReply{
		ReplyType: 0, // 0 = envelope_reply
		EnvelopeReply: &pigeonhole.CourierEnvelopeReply{
			EnvelopeHash: *envHash,
			ReplyIndex:   replyIndex,
			PayloadLen:   0,
			Payload:      nil,
			ErrorCode:    1, // Error code for timeout
		},
	}
}

func (e *Courier) RegisterConsumer(s *cborplugin.Server) {
	e.write = s.Write
}

func (e *Courier) SetWriteFunc(writeFunc func(cborplugin.Command)) {
	e.write = writeFunc
}
