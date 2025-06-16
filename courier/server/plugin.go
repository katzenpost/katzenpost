// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/client2/constants"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	pigeonholeCommon "github.com/katzenpost/katzenpost/pigeonhole/common"
	"github.com/katzenpost/katzenpost/replica/common"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

// Error message constants
var (
	errFailedToReadBoxFromReplica = errors.New("failed to read Box from replica")
	errInvalidDestinationID       = errors.New("invalid destination ID")
	errConnectionNotFound         = errors.New("connection not found")
	errNilEnvelopeHash            = errors.New("envelope hash is nil")
	errNilDEKElements             = errors.New("DEK array contains nil elements")
	errCBORDecodingFailed         = errors.New("CBOR decoding failed")
	errStreamingDecoderFailed     = errors.New("streaming decoder failed")
	errReplicaTimeout             = errors.New("replica timeout")
	errInvalidReplicaID           = errors.New("invalid replica ID")
	errCacheCorruption            = errors.New("cache corruption detected")
	errPKIDocumentUnavailable     = errors.New("PKI document unavailable")
	errInvalidEpoch               = errors.New("invalid epoch")
	errMKEMEncapsulationFailed    = errors.New("MKEM encapsulation failed")
	errMKEMDecryptionFailed       = errors.New("MKEM decryption failed")
	errBACAPDecryptionFailed      = errors.New("BACAP decryption failed")
	errTombstoneWriteFailed       = errors.New("tombstone write failed")
	errEmptySequence              = errors.New("empty sequence")
	errGeometryViolation          = errors.New("message violates geometry constraints")
)

// Copy command error codes - using centralized error codes
const (
	copyErrorSuccess           = pigeonholeCommon.CopyErrorSuccess
	copyErrorInvalidWriteCap   = pigeonholeCommon.CopyErrorInvalidWriteCap
	copyErrorReadCapDerivation = pigeonholeCommon.CopyErrorReadCapDerivation
	copyErrorRead              = pigeonholeCommon.CopyErrorRead
	copyErrorEmptySequence     = pigeonholeCommon.CopyErrorEmptySequence
	copyErrorBACAPDecryption   = pigeonholeCommon.CopyErrorBACAPDecryption
	copyErrorCBORDecoding      = pigeonholeCommon.CopyErrorCBORDecoding
	copyErrorStreamingDecoder  = pigeonholeCommon.CopyErrorStreamingDecoder
	copyErrorReplicaTimeout    = pigeonholeCommon.CopyErrorReplicaTimeout
	copyErrorMKEMDecryption    = pigeonholeCommon.CopyErrorMKEMDecryption
	copyErrorTombstoneWrite    = pigeonholeCommon.CopyErrorTombstoneWrite
	copyErrorReplicaNotFound   = pigeonholeCommon.CopyErrorReplicaNotFound
	copyErrorReplicaDatabase   = pigeonholeCommon.CopyErrorReplicaDatabase
	copyErrorReplicaInternal   = pigeonholeCommon.CopyErrorReplicaInternal
)

// CourierEnvelope operation error codes - using centralized error codes
const (
	envelopeErrorSuccess            = pigeonholeCommon.EnvelopeErrorSuccess
	envelopeErrorInvalidEnvelope    = pigeonholeCommon.EnvelopeErrorInvalidEnvelope
	envelopeErrorNilEnvelopeHash    = pigeonholeCommon.EnvelopeErrorNilEnvelopeHash
	envelopeErrorNilDEKElements     = pigeonholeCommon.EnvelopeErrorNilDEKElements
	envelopeErrorInvalidReplicaID   = pigeonholeCommon.EnvelopeErrorInvalidReplicaID
	envelopeErrorReplicaTimeout     = pigeonholeCommon.EnvelopeErrorReplicaTimeout
	envelopeErrorConnectionFailure  = pigeonholeCommon.EnvelopeErrorConnectionFailure
	envelopeErrorCacheCorruption    = pigeonholeCommon.EnvelopeErrorCacheCorruption
	envelopeErrorPKIUnavailable     = pigeonholeCommon.EnvelopeErrorPKIUnavailable
	envelopeErrorInvalidEpoch       = pigeonholeCommon.EnvelopeErrorInvalidEpoch
	envelopeErrorMKEMFailure        = pigeonholeCommon.EnvelopeErrorMKEMFailure
	envelopeErrorReplicaUnavailable = pigeonholeCommon.EnvelopeErrorReplicaUnavailable
	envelopeErrorInternalError      = pigeonholeCommon.EnvelopeErrorInternalError
)

// General courier error codes - using centralized error codes
const (
	courierErrorSuccess         = pigeonholeCommon.CourierErrorSuccess
	courierErrorInvalidCommand  = pigeonholeCommon.CourierErrorInvalidCommand
	courierErrorCBORDecoding    = pigeonholeCommon.CourierErrorCBORDecoding
	courierErrorDispatchFailure = pigeonholeCommon.CourierErrorDispatchFailure
	courierErrorConnectionLost  = pigeonholeCommon.CourierErrorConnectionLost
	courierErrorInternalError   = pigeonholeCommon.CourierErrorInternalError
)

// copyErrorToString returns a human-readable string for copy error codes
func copyErrorToString(errorCode uint8) string {
	return pigeonholeCommon.CopyErrorToString(errorCode)
}

// envelopeErrorToString returns a human-readable string for envelope error codes
func envelopeErrorToString(errorCode uint8) string {
	return pigeonholeCommon.EnvelopeErrorToString(errorCode)
}

// courierErrorToString returns a human-readable string for general courier error codes
func courierErrorToString(errorCode uint8) string {
	return pigeonholeCommon.CourierErrorToString(errorCode)
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
	pigeonholeGeo  *replicaCommon.Geometry

	dedupCacheLock sync.RWMutex
	dedupCache     map[[hash.HashSize]byte]*CourierBookKeeping

	copyCacheLock sync.RWMutex
	copyCache     map[[hash.HashSize]byte]chan *commands.ReplicaMessageReply

	pendingReadLock sync.RWMutex
	pendingReads    map[[hash.HashSize]byte]*PendingReadRequest
}

// NewCourier returns a new Courier type.
func NewCourier(s *Server, cmds *commands.Commands, scheme nike.Scheme) *Courier {
	pigeonholeGeo := replicaCommon.GeometryFromSphinxGeometry(s.cfg.SphinxGeometry, scheme)

	courier := &Courier{
		server:         s,
		log:            s.logBackend.GetLogger("courier"),
		cmds:           cmds,
		geo:            s.cfg.SphinxGeometry,
		envelopeScheme: scheme,
		pigeonholeGeo:  pigeonholeGeo,
		dedupCache:     make(map[[hash.HashSize]byte]*CourierBookKeeping),
		copyCache:      make(map[[hash.HashSize]byte]chan *commands.ReplicaMessageReply),
		pendingReads:   make(map[[hash.HashSize]byte]*PendingReadRequest),
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
		e.handleCopyReply(reply)
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
		e.log.Warningf("CacheReply: replica ID %d not found in IntermediateReplicas %v for envelope hash %x", reply.ReplicaID, entry.IntermediateReplicas, reply.EnvelopeHash)
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
	e.log.Debugf("BUG: received an unknown EnvelopeHash %x from a replica reply", reply.EnvelopeHash)

	currentEpoch := e.getCurrentEpoch()
	newEntry := &CourierBookKeeping{
		Epoch:                currentEpoch,
		IntermediateReplicas: [2]uint8{reply.ReplicaID, 255}, // 255 indicates unknown
		EnvelopeReplies:      [2]*commands.ReplicaMessageReply{nil, nil},
	}

	if reply.ReplicaID < 2 {
		e.log.Debugf("CacheReply: creating new cache entry and storing reply from replica %d at index %d", reply.ReplicaID, reply.ReplicaID)
		newEntry.EnvelopeReplies[reply.ReplicaID] = reply
	} else {
		e.log.Warningf("CacheReply: invalid replica ID %d for envelope hash %x", reply.ReplicaID, reply.EnvelopeHash)
	}

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
	e.pendingReadLock.Lock()
	defer e.pendingReadLock.Unlock()

	pendingRequest, exists := e.pendingReads[*reply.EnvelopeHash]
	if !exists {
		return false
	}

	// Check if the request has timed out
	if time.Now().After(pendingRequest.Timeout) {
		e.log.Debugf("Pending read request for envelope hash %x has timed out, removing", reply.EnvelopeHash)
		delete(e.pendingReads, *reply.EnvelopeHash)
		return false
	}

	// Remove the pending request since we're about to fulfill it
	delete(e.pendingReads, *reply.EnvelopeHash)

	// Create the reply with the replica data
	courierReply := &common.CourierQueryReply{
		CourierEnvelopeReply: &common.CourierEnvelopeReply{
			EnvelopeHash: reply.EnvelopeHash,
			ReplyIndex:   reply.ReplicaID, // Use the replica ID as the reply index
			Payload:      reply.EnvelopeReply,
			ErrorCode:    envelopeErrorSuccess,
		},
		CopyCommandReply: nil,
	}

	// Send the immediate reply
	go func() {
		e.write(&cborplugin.Response{
			ID:      pendingRequest.RequestID,
			SURB:    pendingRequest.SURB,
			Payload: courierReply.Bytes(),
		})
	}()

	return true
}

// storePendingReadRequest stores a pending read request with a 4-second timeout
func (e *Courier) storePendingReadRequest(envHash *[hash.HashSize]byte, requestID uint64, surb []byte) {
	e.pendingReadLock.Lock()
	defer e.pendingReadLock.Unlock()

	// Set 4-second timeout as requested
	timeout := time.Now().Add(4 * time.Second)

	e.pendingReads[*envHash] = &PendingReadRequest{
		RequestID: requestID,
		SURB:      surb,
		Timeout:   timeout,
	}

	e.log.Debugf("Stored pending read request for envelope hash %x with 4-second timeout", envHash)

	// Start a goroutine to clean up expired requests
	go e.cleanupExpiredRequest(envHash, timeout)
}

// cleanupExpiredRequest removes a pending request after its timeout expires
func (e *Courier) cleanupExpiredRequest(envHash *[hash.HashSize]byte, timeout time.Time) {
	// Wait until the timeout expires
	time.Sleep(time.Until(timeout))

	e.pendingReadLock.Lock()
	defer e.pendingReadLock.Unlock()

	// Check if the request is still there and has expired
	if pendingRequest, exists := e.pendingReads[*envHash]; exists && time.Now().After(pendingRequest.Timeout) {
		delete(e.pendingReads, *envHash)
		e.log.Debugf("Cleaned up expired pending read request for envelope hash %x", envHash)
	}
}

func (e *Courier) handleCourierEnvelope(courierMessage *common.CourierEnvelope) error {
	e.log.Debugf("Copy: Processing CourierEnvelope (IsRead=%t)", courierMessage.IsRead)

	// Log CourierEnvelope size against geometry constraints (no longer rejecting)
	envelopeSize := len(courierMessage.Bytes())
	maxEnvelopeSize := max(e.pigeonholeGeo.CourierQueryReadLength, e.pigeonholeGeo.CourierQueryWriteLength)
	if envelopeSize > maxEnvelopeSize {
		e.log.Infof("WARNING: Oversized CourierEnvelope: %d bytes > %d bytes (geometry limit) - processing anyway",
			envelopeSize, maxEnvelopeSize)
	} else {
		e.log.Debugf("CourierEnvelope size OK: %d bytes <= %d bytes (geometry limit)",
			envelopeSize, maxEnvelopeSize)
	}

	// For write operations, log MKEM ciphertext size (no longer rejecting)
	if !courierMessage.IsRead {
		expectedCiphertextSize := e.pigeonholeGeo.ExpectedMKEMCiphertextSizeForWrite()
		actualCiphertextSize := len(courierMessage.Ciphertext)

		if actualCiphertextSize != expectedCiphertextSize {
			e.log.Infof("WARNING: Write ciphertext size mismatch: %d bytes, expected %d bytes (geometry constraint) - processing anyway",
				actualCiphertextSize, expectedCiphertextSize)
		} else {
			e.log.Debugf("Write ciphertext size validation passed: %d bytes", actualCiphertextSize)
		}
	}

	replicas := make([]*commands.ReplicaMessage, 2)

	// Validate DEK array elements are not nil before using them
	if courierMessage.DEK[0] == nil || courierMessage.DEK[1] == nil {
		e.log.Errorf("handleCourierEnvelope: CourierEnvelope DEK array contains nil elements")
		return errNilDEKElements
	}

	firstReplicaID := courierMessage.IntermediateReplicas[0]
	replicas[0] = &commands.ReplicaMessage{
		Cmds:   e.cmds,
		Geo:    e.geo,
		Scheme: e.envelopeScheme,

		SenderEPubKey: courierMessage.SenderEPubKey,
		DEK:           courierMessage.DEK[0],
		Ciphertext:    courierMessage.Ciphertext,
	}
	e.server.SendMessage(firstReplicaID, replicas[0])

	secondReplicaID := courierMessage.IntermediateReplicas[1]
	replicas[1] = &commands.ReplicaMessage{
		Cmds:   e.cmds,
		Geo:    e.geo,
		Scheme: e.envelopeScheme,

		SenderEPubKey: courierMessage.SenderEPubKey,
		DEK:           courierMessage.DEK[1],
		Ciphertext:    courierMessage.Ciphertext,
	}
	e.server.SendMessage(secondReplicaID, replicas[1])
	return nil
}

func (e *Courier) handleNewMessage(envHash *[hash.HashSize]byte, courierMessage *common.CourierEnvelope) *common.CourierQueryReply {
	if err := e.handleCourierEnvelope(courierMessage); err != nil {
		e.log.Errorf("Failed to handle courier envelope: %s", err)
		if err == errNilDEKElements {
			return e.createEnvelopeErrorReply(envHash, envelopeErrorNilDEKElements)
		}
		return e.createEnvelopeErrorReply(envHash, envelopeErrorInternalError)
	}

	reply := &common.CourierQueryReply{
		CourierEnvelopeReply: &common.CourierEnvelopeReply{
			EnvelopeHash: envHash,
			ReplyIndex:   0,
			Payload:      nil,
			ErrorCode:    envelopeErrorSuccess,
		},
		CopyCommandReply: nil,
	}
	return reply
}

func (e *Courier) handleOldMessage(cacheEntry *CourierBookKeeping, envHash *[hash.HashSize]byte, courierMessage *common.CourierEnvelope) *common.CourierQueryReply {
	e.log.Debugf("handleOldMessage called for envelope hash: %x, requested ReplyIndex: %d", envHash, courierMessage.ReplyIndex)

	// Check if cacheEntry is nil before accessing its fields
	if cacheEntry == nil {
		e.log.Debugf("Cache entry is nil, no replies available")
		return e.createEnvelopeErrorReply(envHash, envelopeErrorCacheCorruption)
	}

	envelopeReply := &common.CourierEnvelopeReply{
		EnvelopeHash: envHash,
		ReplyIndex:   courierMessage.ReplyIndex,
		ErrorCode:    envelopeErrorSuccess,
	}

	// Log cache state
	reply0Available := cacheEntry.EnvelopeReplies[0] != nil
	reply1Available := cacheEntry.EnvelopeReplies[1] != nil
	e.log.Debugf("Cache state - Reply[0]: %v, Reply[1]: %v", reply0Available, reply1Available)

	if cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex] != nil {
		e.log.Debugf("Found reply at requested index %d", courierMessage.ReplyIndex)
		envelopeReply.Payload = cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex].EnvelopeReply
	} else if cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex^1] != nil {
		e.log.Debugf("No reply at requested index %d, checking alternate index %d", courierMessage.ReplyIndex, courierMessage.ReplyIndex^1)
		envelopeReply.Payload = cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex^1].EnvelopeReply
		envelopeReply.ReplyIndex = courierMessage.ReplyIndex ^ 1
	} else {
		e.log.Debugf("No replies available in cache")
	}

	reply := &common.CourierQueryReply{
		CourierEnvelopeReply: envelopeReply,
		CopyCommandReply:     nil,
	}

	e.log.Debugf("handleOldMessage returning payload length: %d", len(envelopeReply.Payload))
	return reply
}

func (e *Courier) OnCommand(cmd cborplugin.Command) error {
	var request *cborplugin.Request
	switch r := cmd.(type) {
	case *cborplugin.Request:
		request = r
	default:
		return errors.New("Bug in courier-plugin: received invalid Command type")
	}

	// Log message size against geometry constraints (no longer rejecting)
	maxQueryLength := max(e.pigeonholeGeo.CourierQueryReadLength, e.pigeonholeGeo.CourierQueryWriteLength)
	if len(request.Payload) > maxQueryLength {
		e.log.Infof("WARNING: Oversized CourierQuery: %d bytes > %d bytes (geometry limit) - processing anyway",
			len(request.Payload), maxQueryLength)
	} else {
		e.log.Debugf("CourierQuery size OK: %d bytes <= %d bytes (geometry limit)",
			len(request.Payload), maxQueryLength)
	}

	courierQuery, err := common.CourierQueryFromBytes(request.Payload)
	if err != nil {
		e.log.Debugf("Failed to decode CourierQuery CBOR blob: %s", err)
		// Send error reply back to client
		errorReply := &common.CourierQueryReply{
			CourierEnvelopeReply: &common.CourierEnvelopeReply{
				ErrorCode: envelopeErrorInvalidEnvelope,
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
	if courierQuery.CourierEnvelope != nil {
		reply := e.cacheHandleCourierEnvelope(courierQuery.CourierEnvelope, request.ID, request.SURB)

		go func() {
			// send reply
			e.write(&cborplugin.Response{
				ID:      request.ID,
				SURB:    request.SURB,
				Payload: reply.Bytes(),
			})
		}()
	}

	// Handle CopyCommand if present
	if courierQuery.CopyCommand != nil {
		e.log.Debugf("CopyCommand received")

		// implementing it now motherfucker
		if courierQuery.CopyCommand.WriteCap == nil {
			e.log.Debugf("CopyCommand received with nil WriteCap")
			return errors.New("CopyCommand received with nil WriteCap")
		}

		reply := e.handleCopyCommand(courierQuery.CopyCommand)

		go func() {
			e.write(&cborplugin.Response{
				ID:      request.ID,
				SURB:    request.SURB,
				Payload: reply.Bytes(),
			})
		}()
	}

	return nil
}

func (e *Courier) cacheHandleCourierEnvelope(courierMessage *common.CourierEnvelope, requestID uint64, surb []byte) *common.CourierQueryReply {
	envHash := courierMessage.EnvelopeHash()

	e.dedupCacheLock.RLock()
	cacheEntry, ok := e.dedupCache[*envHash]
	e.dedupCacheLock.RUnlock()

	if ok {
		e.log.Debugf("OnCommand: Found cached entry for envelope hash %x, calling handleOldMessage", envHash)
		return e.handleOldMessage(cacheEntry, envHash, courierMessage)
	}

	e.log.Debugf("OnCommand: No cached entry for envelope hash %x, calling handleNewMessage", envHash)

	// For read requests, store pending request info for immediate reply proxying
	if courierMessage.IsRead {
		e.storePendingReadRequest(envHash, requestID, surb)
	}

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

// handleCopycommad reads all the boxes in the given BACAP sequence and interprets their
// plaintext contents as CourierEnvelopes. It then sends all those CourierEnvelopes to the
// specified intermediate replicas. Lastly it overwrites the initial sequence with tombstones.
func (e *Courier) handleCopyCommand(copyCmd *common.CopyCommand) *common.CourierQueryReply {
	statefulReader, err := e.createStatefulReader(copyCmd.WriteCap)
	if err != nil {
		e.log.Debugf("Failed to create stateful reader: %s", err)
		return e.createCopyErrorReply(copyErrorReadCapDerivation)
	}

	numBoxes, err := e.processBoxesStreaming(statefulReader)
	if err != nil {
		e.log.Debugf("Failed to process boxes: %s", err)
		// Map specific errors to specific error codes
		switch err {
		case errEmptySequence:
			return e.createCopyErrorReply(copyErrorEmptySequence)
		case errBACAPDecryptionFailed:
			return e.createCopyErrorReply(copyErrorBACAPDecryption)
		case errStreamingDecoderFailed:
			return e.createCopyErrorReply(copyErrorStreamingDecoder)
		case errReplicaTimeout:
			return e.createCopyErrorReply(copyErrorReplicaTimeout)
		case errMKEMDecryptionFailed:
			return e.createCopyErrorReply(copyErrorMKEMDecryption)
		default:
			return e.createCopyErrorReply(copyErrorRead)
		}
	}

	// Write tombstones to all the Boxes in the sequence
	err = e.writeTombstones(copyCmd.WriteCap, numBoxes)
	if err != nil {
		e.log.Debugf("Failed to write tombstones: %s", err)
		return e.createCopyErrorReply(copyErrorTombstoneWrite)
	}

	return e.createCopySuccessReply()
}

func (e *Courier) writeTombstones(writeCap *bacap.BoxOwnerCap, numBoxes int) error {
	statefulWriter, err := bacap.NewStatefulWriter(writeCap, constants.PIGEONHOLE_CTX)
	if err != nil {
		e.log.Debugf("Failed to create StatefulWriter for tombstones: %s", err)
		return err
	}

	// Create tombstone data (all zeros) and pad it using the new helper function
	tombstoneData := make([]byte, 0) // Empty data for tombstones
	tombstonePayload, err := replicaCommon.CreatePaddedPayload(tombstoneData, e.pigeonholeGeo.BoxPayloadLength)
	if err != nil {
		e.log.Debugf("Failed to create padded tombstone payload: %s", err)
		return err
	}

	// Write tombstones using the deterministic nature of BACAP BoxIDs
	// The StatefulWriter will generate the same BoxIDs as the original sequence
	for i := 0; i < numBoxes; i++ {
		isLast := (i == numBoxes-1)
		e.log.Debugf("Writing tombstone %d/%d (IsLast=%t)", i+1, numBoxes, isLast)

		err = e.createAndSendTombstoneEnvelope(statefulWriter, tombstonePayload, isLast)
		if err != nil {
			e.log.Debugf("Failed to write tombstone %d: %s", i+1, err)
			return err
		}
	}

	e.log.Debugf("Successfully wrote %d tombstones", numBoxes)
	return nil
}

// createAndSendTombstoneEnvelope creates a tombstone envelope and sends it to replicas
func (e *Courier) createAndSendTombstoneEnvelope(statefulWriter *bacap.StatefulWriter, tombstonePayload []byte, isLast bool) error {
	e.validateTombstonePayload(tombstonePayload)

	boxID, msg, err := e.encryptTombstonePayload(statefulWriter, tombstonePayload, isLast)
	if err != nil {
		return err
	}

	replicaIndices, replicaPubKeys, err := e.prepareReplicaKeysForTombstone(&boxID)
	if err != nil {
		return err
	}

	courierEnvelope, err := e.createTombstoneCourierEnvelope(msg, replicaIndices, replicaPubKeys)
	if err != nil {
		return err
	}

	return e.sendTombstoneEnvelope(courierEnvelope, &boxID, replicaIndices)
}

// validateTombstonePayload validates and logs tombstone payload size
func (e *Courier) validateTombstonePayload(tombstonePayload []byte) {
	maxPaddedPayloadLength := e.pigeonholeGeo.BoxPayloadLength + 4
	if len(tombstonePayload) > maxPaddedPayloadLength {
		e.log.Infof("WARNING: Oversized tombstone payload: %d bytes > %d bytes (padded geometry limit) - processing anyway",
			len(tombstonePayload), maxPaddedPayloadLength)
	} else {
		e.log.Debugf("Tombstone payload size OK: %d bytes <= %d bytes (padded geometry limit)",
			len(tombstonePayload), maxPaddedPayloadLength)
	}
}

// encryptTombstonePayload encrypts the tombstone payload and creates the write request
func (e *Courier) encryptTombstonePayload(statefulWriter *bacap.StatefulWriter, tombstonePayload []byte, isLast bool) ([bacap.BoxIDSize]byte, *common.ReplicaInnerMessage, error) {
	boxID, ciphertext, sigraw, err := statefulWriter.EncryptNext(tombstonePayload)
	if err != nil {
		e.log.Debugf("Failed to encrypt tombstone payload: %s", err)
		return [bacap.BoxIDSize]byte{}, nil, err
	}

	// Convert signature to array
	sig := [bacap.SignatureSize]byte{}
	copy(sig[:], sigraw)

	// Create ReplicaWrite command for the tombstone
	writeRequest := &commands.ReplicaWrite{
		BoxID:     &boxID,
		Signature: &sig,
		Payload:   ciphertext,
		IsLast:    isLast,
	}

	// Create ReplicaInnerMessage
	msg := &common.ReplicaInnerMessage{
		ReplicaWrite: writeRequest,
	}

	return boxID, msg, nil
}

// prepareReplicaKeysForTombstone prepares replica keys and indices for tombstone encryption
func (e *Courier) prepareReplicaKeysForTombstone(boxID *[bacap.BoxIDSize]byte) ([2]uint8, []nike.PublicKey, error) {
	doc := e.server.PKI.PKIDocument()
	if doc == nil {
		e.log.Debugf("PKI document not available for tombstone write")
		return [2]uint8{}, nil, errors.New("PKI document not available")
	}

	shardedReplicas, err := replicaCommon.GetShards(boxID, doc)
	if err != nil {
		e.log.Debugf("Failed to get shards for tombstone BoxID %x: %s", boxID[:8], err)
		return [2]uint8{}, nil, err
	}

	if len(shardedReplicas) != 2 {
		e.log.Debugf("Expected 2 sharded replicas for tombstone, got %d for BoxID %x", len(shardedReplicas), boxID[:8])
		return [2]uint8{}, nil, errors.New("invalid number of sharded replicas")
	}

	replicaEpoch, _, _ := common.ReplicaNow()
	replicaPubKeys := make([]nike.PublicKey, 2)
	var replicaIndices [2]uint8

	for i, shardedReplica := range shardedReplicas {
		replicaIndex := e.findReplicaIndexByDescriptor(shardedReplica, doc)
		if replicaIndex == -1 {
			e.log.Debugf("Could not find sharded replica %d in StorageReplicas for tombstone BoxID %x", i, boxID[:8])
			return [2]uint8{}, nil, errors.New("replica not found in PKI document")
		}

		replicaIndices[i] = uint8(replicaIndex)

		// Get replica public key for this epoch
		replicaPubKey := doc.StorageReplicas[replicaIndex].EnvelopeKeys[replicaEpoch]
		replicaPubKeys[i], err = common.NikeScheme.UnmarshalBinaryPublicKey(replicaPubKey)
		if err != nil {
			e.log.Debugf("Failed to unmarshal replica %d public key for tombstone: %s", replicaIndex, err)
			return [2]uint8{}, nil, err
		}
	}

	return replicaIndices, replicaPubKeys, nil
}

// createTombstoneCourierEnvelope creates the MKEM-encrypted courier envelope for the tombstone
func (e *Courier) createTombstoneCourierEnvelope(msg *common.ReplicaInnerMessage, replicaIndices [2]uint8, replicaPubKeys []nike.PublicKey) (*common.CourierEnvelope, error) {
	mkemPrivateKey, mkemCiphertext := common.MKEMNikeScheme.Encapsulate(replicaPubKeys, msg.Bytes())
	mkemPublicKey := mkemPrivateKey.Public()

	// Validate DEK ciphertexts are not nil
	if mkemCiphertext.DEKCiphertexts[0] == nil || mkemCiphertext.DEKCiphertexts[1] == nil {
		e.log.Debugf("MKEM encapsulation failed for tombstone - nil DEK ciphertexts")
		return nil, errors.New("MKEM encapsulation failed")
	}

	return &common.CourierEnvelope{
		SenderEPubKey:        mkemPublicKey.Bytes(),
		IntermediateReplicas: replicaIndices,
		DEK:                  [2]*[mkem.DEKSize]byte{mkemCiphertext.DEKCiphertexts[0], mkemCiphertext.DEKCiphertexts[1]},
		Ciphertext:           mkemCiphertext.Envelope,
		IsRead:               false,
	}, nil
}

// sendTombstoneEnvelope sends the tombstone envelope to replicas
func (e *Courier) sendTombstoneEnvelope(courierEnvelope *common.CourierEnvelope, boxID *[bacap.BoxIDSize]byte, replicaIndices [2]uint8) error {
	e.log.Debugf("Sending tombstone envelope for BoxID %x to replicas %v", boxID[:8], replicaIndices)
	err := e.handleCourierEnvelope(courierEnvelope)
	if err != nil {
		e.log.Debugf("Failed to send tombstone envelope for BoxID %x: %s", boxID[:8], err)
		return err
	}

	e.log.Debugf("Successfully sent tombstone for BoxID %x", boxID[:8])
	return nil
}

func (e *Courier) createStatefulReader(writeCap *bacap.BoxOwnerCap) (*bacap.StatefulReader, error) {
	readcap := writeCap.UniversalReadCap()
	statefulReader, err := bacap.NewStatefulReader(readcap, constants.PIGEONHOLE_CTX)
	if err != nil {
		e.log.Debugf("Failed to create stateful reader from readcap: %s", err)
		return nil, err
	}
	return statefulReader, nil
}

func (e *Courier) processBoxesStreaming(statefulReader *bacap.StatefulReader) (int, error) {
	// Create a streaming CBOR decoder that processes envelopes as they become available
	streamingDecoder := NewStreamingCBORDecoder(func(envelope *common.CourierEnvelope) {
		if err := e.handleCourierEnvelope(envelope); err != nil {
			e.log.Errorf("Failed to handle courier envelope: %s", err)
		}
	})

	boxCount, err := e.processAllBoxes(statefulReader, streamingDecoder)
	if err != nil {
		return 0, err
	}

	// Process any remaining partial data
	err = streamingDecoder.Finalize()
	if err != nil {
		e.log.Debugf("Failed to finalize streaming decoder: %s", err)
		return 0, errStreamingDecoderFailed
	}

	e.log.Debugf("Copy: Successfully processed %d CourierEnvelopes and wrote %d boxes to destination", streamingDecoder.processedEnvelopes, boxCount)
	return boxCount, nil
}

// processAllBoxes reads and processes all boxes in the sequence
func (e *Courier) processAllBoxes(statefulReader *bacap.StatefulReader, streamingDecoder *StreamingCBORDecoder) (int, error) {
	boxCount := 0

	// Read boxes sequentially using the StatefulReader
	for {
		boxID, err := e.getNextBoxID(statefulReader, boxCount)
		if err != nil {
			return boxCount, err
		}
		boxCount++

		replicaReadReply, err := e.readBoxFromReplica(boxID)
		if err != nil {
			return 0, e.handleReadBoxError(err)
		}

		boxPlaintext, boxPaddedPlaintext, err := e.decryptAndExtractBox(statefulReader, boxID, replicaReadReply)
		if err != nil {
			return 0, err
		}

		e.validateBoxSize(boxPaddedPlaintext)

		err = streamingDecoder.ProcessChunk(boxPlaintext)
		if err != nil {
			e.log.Debugf("Failed to process box chunk: %s", err)
			return 0, errStreamingDecoderFailed
		}

		// Check if this was the last box
		if replicaReadReply.IsLast {
			break
		}
	}

	return boxCount, nil
}

// getNextBoxID gets the next BoxID to read, handling empty sequence detection
func (e *Courier) getNextBoxID(statefulReader *bacap.StatefulReader, boxCount int) (*[bacap.BoxIDSize]byte, error) {
	boxID, err := statefulReader.NextBoxID()
	if err != nil {
		// If we can't get the first BoxID, the sequence is empty
		e.log.Debugf("Empty sequence detected: %s", err)
		if boxCount == 0 {
			return nil, errEmptySequence
		}
		return nil, err
	}
	return boxID, nil
}

// handleReadBoxError handles errors from reading boxes from replicas
func (e *Courier) handleReadBoxError(err error) error {
	e.log.Debugf("Failed to read Box from replica: %s", err)
	if err == errFailedToReadBoxFromReplica {
		return errReplicaTimeout
	}
	return err
}

// decryptAndExtractBox decrypts a box and extracts the plaintext data
func (e *Courier) decryptAndExtractBox(statefulReader *bacap.StatefulReader, boxID *[bacap.BoxIDSize]byte, replicaReadReply *common.ReplicaReadReply) ([]byte, []byte, error) {
	// Validate signature before decryption
	if replicaReadReply.Signature == nil {
		e.log.Debugf("Replica read reply has nil signature for BoxID %x", boxID[:8])
		return nil, nil, errBACAPDecryptionFailed
	}

	// Decrypt the box using BACAP
	boxPaddedPlaintext, err := statefulReader.DecryptNext(constants.PIGEONHOLE_CTX, *boxID, replicaReadReply.Payload, *replicaReadReply.Signature)
	if err != nil {
		e.log.Debugf("Failed to decrypt box: %s", err)
		return nil, nil, errBACAPDecryptionFailed
	}

	// Extract the original data from the padded payload
	boxPlaintext, err := replicaCommon.ExtractDataFromPaddedPayload(boxPaddedPlaintext)
	if err != nil {
		e.log.Debugf("Failed to extract data from padded payload: %s", err)
		return nil, nil, errBACAPDecryptionFailed
	}

	return boxPlaintext, boxPaddedPlaintext, nil
}

// validateBoxSize validates the box size against geometry constraints
func (e *Courier) validateBoxSize(boxPaddedPlaintext []byte) {
	maxPaddedPayloadLength := e.pigeonholeGeo.BoxPayloadLength + 4
	if len(boxPaddedPlaintext) > maxPaddedPayloadLength {
		e.log.Infof("WARNING: Oversized box plaintext: %d bytes > %d bytes (padded geometry limit) - processing anyway",
			len(boxPaddedPlaintext), maxPaddedPayloadLength)
	} else {
		e.log.Debugf("Box plaintext size OK: %d bytes <= %d bytes (padded geometry limit)",
			len(boxPaddedPlaintext), maxPaddedPayloadLength)
	}
}

// StreamingCBORDecoder processes CBOR data incrementally, decoding and handling
// CourierEnvelopes as soon as they become available, without accumulating all data
type StreamingCBORDecoder struct {
	buffer             *bytes.Buffer
	decoder            *cbor.Decoder
	handleEnvelope     func(*common.CourierEnvelope)
	processedEnvelopes int
}

// NewStreamingCBORDecoder creates a new streaming CBOR decoder
func NewStreamingCBORDecoder(handleEnvelope func(*common.CourierEnvelope)) *StreamingCBORDecoder {
	buffer := bytes.NewBuffer(nil)
	decMode, _ := cbor.DecOptions{}.DecMode() // Error handling done in ProcessChunk
	decoder := decMode.NewDecoder(buffer)

	return &StreamingCBORDecoder{
		buffer:         buffer,
		decoder:        decoder,
		handleEnvelope: handleEnvelope,
	}
}

// ProcessChunk adds new data and processes any complete envelopes
func (s *StreamingCBORDecoder) ProcessChunk(data []byte) error {
	// Add new data to buffer
	s.buffer.Write(data)

	// Try to decode and process any complete envelopes
	return s.processAvailableEnvelopes()
}

// Finalize processes any remaining data in the buffer
func (s *StreamingCBORDecoder) Finalize() error {
	return s.processAvailableEnvelopes()
}

// processAvailableEnvelopes attempts to decode envelopes from the current buffer
func (s *StreamingCBORDecoder) processAvailableEnvelopes() error {
	for {
		var envelope common.CourierEnvelope
		err := s.decoder.Decode(&envelope)
		if err != nil {
			// If we can't decode, it likely means we need more data
			// This is normal and expected when we've processed all available complete envelopes
			return nil
		}

		// Successfully decoded an envelope - process it immediately
		s.handleEnvelope(&envelope)
		s.processedEnvelopes++
	}
}

func (e *Courier) createCopyErrorReply(errorCode uint8) *common.CourierQueryReply {
	e.log.Debugf("Copy command failed with error code %d: %s", errorCode, copyErrorToString(errorCode))
	return &common.CourierQueryReply{
		CourierEnvelopeReply: nil,
		CopyCommandReply: &common.CopyCommandReply{
			ErrorCode: errorCode,
		},
	}
}

func (e *Courier) createCopySuccessReply() *common.CourierQueryReply {
	e.log.Debugf("Copy command completed successfully")
	return &common.CourierQueryReply{
		CourierEnvelopeReply: nil,
		CopyCommandReply: &common.CopyCommandReply{
			ErrorCode: copyErrorSuccess,
		},
	}
}

// createEnvelopeErrorReply creates a CourierEnvelopeReply with the specified error code
func (e *Courier) createEnvelopeErrorReply(envHash *[hash.HashSize]byte, errorCode uint8) *common.CourierQueryReply {
	e.log.Debugf("Envelope operation failed with error code %d: %s", errorCode, envelopeErrorToString(errorCode))
	return &common.CourierQueryReply{
		CourierEnvelopeReply: &common.CourierEnvelopeReply{
			EnvelopeHash: envHash,
			ReplyIndex:   0,
			Payload:      nil,
			ErrorCode:    errorCode,
		},
		CopyCommandReply: nil,
	}
}

// createEnvelopeSuccessReply creates a successful CourierEnvelopeReply
func (e *Courier) createEnvelopeSuccessReply(envHash *[hash.HashSize]byte, replyIndex uint8, payload []byte) *common.CourierQueryReply {
	return &common.CourierQueryReply{
		CourierEnvelopeReply: &common.CourierEnvelopeReply{
			EnvelopeHash: envHash,
			ReplyIndex:   replyIndex,
			Payload:      payload,
			ErrorCode:    envelopeErrorSuccess,
		},
		CopyCommandReply: nil,
	}
}

// here we send a read request to the replica and get a reply
func (e *Courier) readBoxFromReplica(boxID *[bacap.BoxIDSize]byte) (*common.ReplicaReadReply, error) {
	e.log.Debugf("Copy: Reading BoxID %x from replica", boxID[:8])

	shardedReplicas, err := e.getShardedReplicas(boxID)
	if err != nil {
		return nil, err
	}

	replicaErrors := make([]uint8, 0, 2)

	// Try reading from the 2 sharded replicas
	for i, shardedReplica := range shardedReplicas {
		reply, err := e.tryReadFromReplica(boxID, i, shardedReplica, &replicaErrors)
		if err == nil && reply != nil {
			e.log.Debugf("Copy: Successfully read BoxID %x from replica %d", boxID[:8], i)
			return reply, nil
		}
	}

	return e.handleAllReplicasFailed(boxID, replicaErrors)
}

// getShardedReplicas gets the sharded replicas for a given BoxID
func (e *Courier) getShardedReplicas(boxID *[bacap.BoxIDSize]byte) ([]*pki.ReplicaDescriptor, error) {
	doc := e.server.PKI.PKIDocument()

	shardedReplicas, err := replicaCommon.GetShards(boxID, doc)
	if err != nil {
		e.log.Debugf("Copy: Failed to get shards for BoxID %x: %s", boxID[:8], err)
		return nil, errFailedToReadBoxFromReplica
	}
	if len(shardedReplicas) != 2 {
		e.log.Debugf("Copy: Expected 2 sharded replicas, got %d for BoxID %x", len(shardedReplicas), boxID[:8])
		return nil, errFailedToReadBoxFromReplica
	}

	return shardedReplicas, nil
}

// prepareReplicaKeys prepares the replica public keys for MKEM encryption
func (e *Courier) prepareReplicaKeys(replicaIndex int, doc *pki.Document) ([]nike.PublicKey, error) {
	replicaEpoch, _, _ := common.ReplicaNow()
	replicaPubKey := doc.StorageReplicas[replicaIndex].EnvelopeKeys[replicaEpoch]
	replicaPubKeys := make([]nike.PublicKey, 1)

	var err error
	replicaPubKeys[0], err = common.NikeScheme.UnmarshalBinaryPublicKey(replicaPubKey)
	if err != nil {
		e.log.Debugf("Copy: Failed to unmarshal replica %d public key: %s", replicaIndex, err)
		return nil, err
	}

	return replicaPubKeys, nil
}

// findReplicaIndexByDescriptor finds the index of a sharded replica in the StorageReplicas slice
func (e *Courier) findReplicaIndexByDescriptor(shardedReplica *pki.ReplicaDescriptor, doc *pki.Document) int {
	for j, storageReplica := range doc.StorageReplicas {
		if bytes.Equal(shardedReplica.IdentityKey, storageReplica.IdentityKey) {
			return j
		}
	}
	return -1
}

// tryReadFromReplica attempts to read from a single replica
func (e *Courier) tryReadFromReplica(boxID *[bacap.BoxIDSize]byte, replicaNum int, shardedReplica *pki.ReplicaDescriptor, replicaErrors *[]uint8) (*common.ReplicaReadReply, error) {
	doc := e.server.PKI.PKIDocument()

	// Find the index of this replica in the StorageReplicas slice
	replicaIndex := e.findReplicaIndexByDescriptor(shardedReplica, doc)
	if replicaIndex == -1 {
		e.log.Debugf("Copy: Could not find sharded replica %d in StorageReplicas for BoxID %x", replicaNum, boxID[:8])
		*replicaErrors = append(*replicaErrors, pigeonholeCommon.ReplicaErrorInvalidEpoch)
		return nil, errFailedToReadBoxFromReplica
	}

	e.log.Debugf("Copy: Trying sharded replica %d (index %d) for BoxID %x", replicaNum, replicaIndex, boxID[:8])

	replicaPubKeys, err := e.prepareReplicaKeys(replicaIndex, doc)
	if err != nil {
		*replicaErrors = append(*replicaErrors, pigeonholeCommon.ReplicaErrorInvalidEpoch)
		return nil, err
	}

	reply, mkemPrivateKey, err := e.sendReplicaQuery(boxID, replicaIndex, replicaPubKeys)
	if err != nil {
		*replicaErrors = append(*replicaErrors, pigeonholeCommon.ReplicaErrorInternalError)
		return nil, err
	}

	return e.processReplicaReply(boxID, replicaIndex, reply, mkemPrivateKey, replicaPubKeys, replicaErrors)
}

// sendReplicaQuery sends a query to a replica and returns the reply and private key
func (e *Courier) sendReplicaQuery(boxID *[bacap.BoxIDSize]byte, replicaIndex int, replicaPubKeys []nike.PublicKey) (*commands.ReplicaMessageReply, nike.PrivateKey, error) {
	readMsg := common.ReplicaRead{
		BoxID: boxID,
	}
	msg := &common.ReplicaInnerMessage{
		ReplicaRead: &readMsg,
	}

	mkemPrivateKey, mkemCiphertext := common.MKEMNikeScheme.Encapsulate(replicaPubKeys, msg.Bytes())
	mkemPublicKey := mkemPrivateKey.Public()

	// Validate DEK is not nil before using it
	if mkemCiphertext.DEKCiphertexts[0] == nil {
		e.log.Debugf("Copy: MKEM encapsulation failed for replica %d", replicaIndex)
		return nil, nil, errFailedToReadBoxFromReplica
	}

	query := &commands.ReplicaMessage{
		Cmds:   e.cmds,
		Geo:    e.geo,
		Scheme: e.envelopeScheme,

		SenderEPubKey: mkemPublicKey.Bytes(),
		DEK:           mkemCiphertext.DEKCiphertexts[0],
		Ciphertext:    mkemCiphertext.Envelope,
	}

	envHash := query.EnvelopeHash()

	e.copyCacheLock.Lock()
	e.copyCache[*envHash] = make(chan *commands.ReplicaMessageReply, 1)
	e.copyCacheLock.Unlock()

	e.server.SendMessage(uint8(replicaIndex), query)

	reply := <-e.copyCache[*envHash]
	delete(e.copyCache, *envHash)

	return reply, mkemPrivateKey, nil
}

// processReplicaReply processes the reply from a replica and validates the response
func (e *Courier) processReplicaReply(boxID *[bacap.BoxIDSize]byte, replicaIndex int, reply *commands.ReplicaMessageReply, mkemPrivateKey nike.PrivateKey, replicaPubKeys []nike.PublicKey, replicaErrors *[]uint8) (*common.ReplicaReadReply, error) {
	e.log.Debugf("Copy: Replica %d reply for BoxID %x: ErrorCode=%d", replicaIndex, boxID[:8], reply.ErrorCode)

	if reply.ErrorCode != 0 {
		e.log.Debugf("Copy: Replica %d returned error code %d (%s), trying next replica", replicaIndex, reply.ErrorCode, pigeonholeCommon.ReplicaErrorToString(reply.ErrorCode))
		*replicaErrors = append(*replicaErrors, reply.ErrorCode)
		return nil, errFailedToReadBoxFromReplica
	}

	rawPlaintext, err := common.MKEMNikeScheme.DecryptEnvelope(mkemPrivateKey, replicaPubKeys[0], reply.EnvelopeReply)
	if err != nil {
		e.log.Debugf("Copy: Failed to decrypt envelope from replica %d: %s", replicaIndex, err)
		*replicaErrors = append(*replicaErrors, pigeonholeCommon.ReplicaErrorInternalError)
		return nil, err
	}

	innerMsg, err := common.ReplicaMessageReplyInnerMessageFromBytes(rawPlaintext)
	if err != nil {
		e.log.Debugf("Copy: Failed to parse inner message from replica %d: %s", replicaIndex, err)
		return nil, err
	}

	if innerMsg.ReplicaReadReply == nil {
		e.log.Debugf("Copy: Replica %d returned nil ReplicaReadReply", replicaIndex)
		return nil, errFailedToReadBoxFromReplica
	}

	if innerMsg.ReplicaReadReply.Signature == nil {
		e.log.Debugf("Copy: Replica %d returned nil signature for BoxID %x, trying next replica", replicaIndex, boxID[:8])
		*replicaErrors = append(*replicaErrors, pigeonholeCommon.ReplicaErrorInvalidSignature)
		return nil, errFailedToReadBoxFromReplica
	}

	return innerMsg.ReplicaReadReply, nil
}

// handleAllReplicasFailed handles the case when all replicas fail to provide valid data
func (e *Courier) handleAllReplicasFailed(boxID *[bacap.BoxIDSize]byte, replicaErrors []uint8) (*common.ReplicaReadReply, error) {
	e.log.Debugf("Copy: All replicas failed to provide valid data for BoxID %x", boxID[:8])

	if len(replicaErrors) > 0 {
		notFoundCount := 0
		for _, errCode := range replicaErrors {
			if errCode == pigeonholeCommon.ReplicaErrorNotFound {
				notFoundCount++
			}
		}

		if notFoundCount > len(replicaErrors)/2 {
			e.log.Debugf("Copy: Majority of replicas (%d/%d) returned 'not found' for BoxID %x", notFoundCount, len(replicaErrors), boxID[:8])
		}
	}

	return nil, errFailedToReadBoxFromReplica
}

func (e *Courier) handleCopyReply(reply *commands.ReplicaMessageReply) {
	e.log.Debugf("handleCopyReply called with envelope hash: %x", reply.EnvelopeHash)

	e.copyCacheLock.RLock()
	replyChan := e.copyCache[*reply.EnvelopeHash]
	e.copyCacheLock.RUnlock()

	replyChan <- reply
}

func (e *Courier) RegisterConsumer(s *cborplugin.Server) {
	e.write = s.Write
}

func (e *Courier) SetWriteFunc(writeFunc func(cborplugin.Command)) {
	e.write = writeFunc
}
