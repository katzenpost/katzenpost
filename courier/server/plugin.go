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

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/client2/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/pigeonhole"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
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
	e.copyCacheLock.RLock()
	ch, isCopy := e.copyCache[*reply.EnvelopeHash]
	e.copyCacheLock.RUnlock()

	if isCopy {
		// Send reply to waiting goroutine for copy command processing
		ch <- reply
		return
	}
	e.CacheReply(reply)
}

func (e *Courier) CacheReply(reply *commands.ReplicaMessageReply) {
	e.log.Debugf("CacheReply called with envelope hash: %x from replica ID: %d", reply.EnvelopeHash, reply.ReplicaID)

	if !e.validateReply(reply) {
		e.log.Errorf("courier/!e.validateReply(reply:%v)", reply)
		return
	}

	// DEBUG: Log which replica sent this reply
	e.dedupCacheLock.Lock()
	entry, ok := e.dedupCache[*reply.EnvelopeHash]
	e.dedupCacheLock.Unlock()
	if ok {
		e.log.Debugf("CacheReply: Reply from replica %d, intermediaries are: %v", reply.ReplicaID, entry.IntermediateReplicas)
	}

	// NOTE: We do NOT send immediate replies for read requests.
	// The ARQ protocol requires:
	// 1. Client sends first request with SURB #1 → Courier sends ACK on SURB #1
	// 2. Client receives ACK, sends second request with SURB #2 (same envelope hash)
	// 3. Courier returns cached payload on SURB #2 via handleOldMessage
	// Trying to send the payload on SURB #1 would fail because the client has moved on to SURB #2.

	e.dedupCacheLock.Lock()
	defer e.dedupCacheLock.Unlock()

	entry2, ok2 := e.dedupCache[*reply.EnvelopeHash]
	if ok2 {
		e.handleExistingEntry(entry2, reply)
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

	e.log.Debug("CacheReply: caching reply")

	return true
}

// handleExistingEntry processes replies for existing cache entries
func (e *Courier) handleExistingEntry(entry *CourierBookKeeping, reply *commands.ReplicaMessageReply) {
	e.log.Errorf("CacheReply: found existing cache entry for envelope hash %x", reply.EnvelopeHash)

	if reply.IsRead && reply.ErrorCode == 0 {
		// we do want to overwrite old entries if we had an error and now don't
		e.log.Errorf("handleExistingEntry: IsRead && ErrorCode == 0: entry=%v reply=%v", entry, reply)
	}

	replyIndex := e.findReplicaIndex(entry, reply.ReplicaID)
	if replyIndex >= 0 {
		e.storeReplyIfEmpty(entry, reply, replyIndex)
	} else {
		// Check if we can accommodate this replica in an unused slot (marked as 255)
		for i, id := range entry.IntermediateReplicas {
			if id == 255 && entry.EnvelopeReplies[i] == nil {
				e.log.Errorf("CacheReply: storing reply from replica %d in unused slot %d", reply.ReplicaID, i)
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
		e.log.Infof("CacheReply: storing reply from replica %d at IntermediateReplicas index %d", reply.ReplicaID, replyIndex)
		entry.EnvelopeReplies[replyIndex] = reply
	} else {
		e.log.Infof("CacheReply: reply from replica %d already cached, ignoring duplicate", reply.ReplicaID)
	}
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

	// Only send immediate reply if this reply contains actual data (successful read)
	// ErrorCode 0 = success, and we need actual envelope data
	if reply.ErrorCode != 0 || len(reply.EnvelopeReply) == 0 {
		e.log.Debugf("tryImmediateReplyProxy: Reply has no data (ErrorCode=%d, EnvelopeReplyLen=%d), not sending immediate reply",
			reply.ErrorCode, len(reply.EnvelopeReply))
		return false
	}

	// Remove the pending request since we're about to fulfill it with actual data
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
		// Determine reply type based on whether there's actual payload data
		var replyType uint8
		if len(reply.EnvelopeReply) > 29 {
			// we sometimes get a small RepliceMessageReply thing here, and we shouldn't return it as data
			// because clientd can't decode it
			replyType = pigeonhole.ReplyTypePayload // Has actual data
			e.log.Errorf("tryImmediateReplyProxy: setting ReplyType:=ReplyTypePayload because len(reply.EnvelopeReply)==%d: %v",
				len(reply.EnvelopeReply), reply)

		} else {
			replyType = pigeonhole.ReplyTypeACK // No data, just acknowledgment
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
	// Set timeout to allow for replica response delays
	seconds := 20
	timeout := time.Now().Add(time.Duration(seconds) * time.Second)

	e.pendingRequestsLock.Lock()
	e.pendingRequests[*envHash] = &PendingReadRequest{
		RequestID: requestID,
		SURB:      surb,
		Timeout:   timeout,
	}
	e.pendingRequestsLock.Unlock()

	e.log.Debugf("Stored pending read request for envelope hash %x with %d-second timeout", envHash, seconds)

	// Start a goroutine to clean up expired requests
	go e.cleanupExpiredRequest(envHash, timeout)
}

// cleanupExpiredRequest removes a pending request after its timeout expires
func (e *Courier) cleanupExpiredRequest(envHash *[hash.HashSize]byte, timeout time.Time) {
	// Wait until the timeout expires
	time.Sleep(time.Until(timeout))

	e.pendingRequestsLock.Lock()

	// Check if the request is still there and has expired
	if pendingRequest, exists := e.pendingRequests[*envHash]; exists && time.Now().After(pendingRequest.Timeout) {
		delete(e.pendingRequests, *envHash)
		e.pendingRequestsLock.Unlock()
		e.log.Debugf("Cleaned up expired pending read request for envelope hash %x", envHash)
		return
	}
	e.pendingRequestsLock.Unlock()
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

// handleNewMessage processes new messages and dispatches them to replicas and then
// returns an immediate ACK reply to confirm receipt and dispatch
func (e *Courier) handleNewMessage(envHash *[hash.HashSize]byte, courierMessage *pigeonhole.CourierEnvelope) *pigeonhole.CourierQueryReply {
	e.log.Debugf("handleNewMessage: Processing new message for envelope hash %x", envHash)

	if err := e.propagateQueryToReplicas(courierMessage); err != nil {
		e.log.Errorf("handleNewMessage: Failed to handle courier envelope: %s", err)
		e.log.Debugf("handleNewMessage: Returning error reply due to internal error")
		return e.createEnvelopeErrorReply(envHash, pigeonhole.EnvelopeErrorPropagationError, courierMessage.ReplyIndex)
	}

	// SUCCESS CASE: Messages were successfully dispatched to replicas
	// Return immediate ACK reply to confirm receipt and dispatch
	// The actual response with data will come later via CacheReply/tryImmediateReplyProxy when replicas respond
	e.log.Debugf("handleNewMessage: Successfully dispatched to replicas, returning immediate ACK reply (ReplyType=%d)",
		pigeonhole.ReplyTypeACK)
	reply := &pigeonhole.CourierQueryReply{
		ReplyType: 0, // 0 = envelope_reply
		EnvelopeReply: &pigeonhole.CourierEnvelopeReply{
			EnvelopeHash: *envHash,
			ReplyIndex:   courierMessage.ReplyIndex,
			ReplyType:    pigeonhole.ReplyTypeACK, // ACK - Request received and dispatched
			PayloadLen:   0,
			Payload:      nil,
			ErrorCode:    pigeonhole.EnvelopeErrorSuccess, // Success - message accepted and dispatched
		},
	}
	return reply
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

	if cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex] != nil {
		entry := cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex]
		payload = entry.EnvelopeReply
		e.log.Debugf("Found reply [len:%d err:%d read:%v] at requested index %d for %v", len(payload), entry.ErrorCode, entry.IsRead, courierMessage.ReplyIndex, envHash)
		if len(payload) == 0 && cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex^1] != nil {
			oentry := cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex^1]
			e.log.Debugf("entry at idx %v is empty; other: [len:%d err:%d read:%v]", courierMessage.ReplyIndex, len(oentry.EnvelopeReply), oentry.ErrorCode, oentry.IsRead)
		}
	} else {
		e.log.Debugf("No reply available at requested index %d", courierMessage.ReplyIndex)
		if cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex^1] != nil {
			courierMessage.ReplyIndex = courierMessage.ReplyIndex ^ 1
			payload = cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex].EnvelopeReply
			e.log.Debugf("But there is a reply for %d, so returning that (envHash:%v)", courierMessage.ReplyIndex, envHash)
		} else {
			payload = nil
		}
	}

	// Determine reply type based on whether there's actual payload data
	var replyType uint8
	if len(payload) > 29 {
		// whatever it is that the courier stuffs in here of length 29
		// cannot be decoded by the clientd. whether that's a bug in the courier or the clientd
		// is unclear, but for now...
		// note that we have the same hack in tryImmediateReplyProxy because the logic
		// to synthesize CourierEnvelopeReply is duplicated there.
		replyType = pigeonhole.ReplyTypePayload // Has actual data
	} else {
		replyType = pigeonhole.ReplyTypeACK // No data, just acknowledgment
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

	switch {
	case courierQuery.Envelope != nil:
		reply := e.cacheHandleCourierEnvelope(courierQuery.QueryType, courierQuery.Envelope, request.ID, request.SURB)

		// Only send reply if it's not nil (nil means ARQ should retry)
		if reply != nil {
			go func() {
				// send reply
				e.write(&cborplugin.Response{
					ID:      request.ID,
					SURB:    request.SURB,
					Payload: reply.Bytes(),
				})
			}()
		}
	case courierQuery.CopyCommand != nil:
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

// handleCopyCommand reads all the boxes in the given BACAP sequence and interprets their
// plaintext contents as CopyStreamElements containing CourierEnvelopes. It reads boxes until
// it finds an element with the IsFinal flag set. It then sends all those CourierEnvelopes to
// the specified intermediate replicas. Lastly it overwrites the initial sequence with tombstones.
func (e *Courier) handleCopyCommand(copyCmd *pigeonhole.CopyCommand) *pigeonhole.CourierQueryReply {
	e.log.Debugf("handleCopyCommand: Processing copy command with WriteCap length %d", copyCmd.WriteCapLen)

	// Deserialize the WriteCap
	writeCap, err := bacap.NewWriteCapFromBytes(copyCmd.WriteCap)
	if err != nil {
		e.log.Errorf("handleCopyCommand: Failed to deserialize WriteCap: %v", err)
		return &pigeonhole.CourierQueryReply{
			ReplyType: 1, // 1 = copy_command_reply
			CopyCommandReply: &pigeonhole.CopyCommandReply{
				ErrorCode: 1, // Error
			},
		}
	}

	// Derive ReadCap from WriteCap
	readCap := writeCap.ReadCap()

	// Create StatefulReader for the temporary channel
	reader, err := bacap.NewStatefulReader(readCap, constants.PIGEONHOLE_CTX)
	if err != nil {
		e.log.Errorf("handleCopyCommand: Failed to create StatefulReader: %v", err)
		return &pigeonhole.CourierQueryReply{
			ReplyType: 1,
			CopyCommandReply: &pigeonhole.CopyCommandReply{
				ErrorCode: 1,
			},
		}
	}

	// Process copy stream box-by-box with bounded memory using streaming envelope decoder.
	// The decoder accumulates chunk data from CopyStreamElements and returns complete
	// CourierEnvelopes which are sent immediately to replicas.
	// We continue reading boxes until we encounter an element with IsFinal flag set.
	var boxIDList [][bacap.BoxIDSize]byte
	decoder := pigeonhole.NewCopyStreamEnvelopeDecoder(e.pigeonholeGeo)
	numEnvelopes := 0
	sawFinal := false

	for !sawFinal {
		// Get next BoxID
		boxID, err := reader.NextBoxID()
		if err != nil {
			e.log.Errorf("handleCopyCommand: Failed to get next BoxID: %v", err)
			return &pigeonhole.CourierQueryReply{
				ReplyType: 1,
				CopyCommandReply: &pigeonhole.CopyCommandReply{
					ErrorCode: 1,
				},
			}
		}
		boxIDList = append(boxIDList, *boxID)

		// Read the box from replicas (raw CopyStreamElement bytes)
		boxPlaintext, err := e.readNextBox(reader, boxID)
		if err != nil {
			e.log.Errorf("handleCopyCommand: Failed to read box %x: %v", boxID[:], err)
			return &pigeonhole.CourierQueryReply{
				ReplyType: 1,
				CopyCommandReply: &pigeonhole.CopyCommandReply{
					ErrorCode: 1,
				},
			}
		}

		// Add box data to streaming envelope decoder
		decoder.AddBoxData(boxPlaintext)

		// Decode any complete envelopes and check for final flag
		envelopes, isFinal, err := decoder.DecodeEnvelopes()
		if err != nil {
			e.log.Errorf("handleCopyCommand: Failed to decode envelopes: %v", err)
			return &pigeonhole.CourierQueryReply{
				ReplyType: 1,
				CopyCommandReply: &pigeonhole.CopyCommandReply{
					ErrorCode: 1,
				},
			}
		}

		// Process each decoded envelope
		for _, envelope := range envelopes {
			// Send envelope immediately to replicas
			if err := e.propagateQueryToReplicas(envelope); err != nil {
				e.log.Errorf("handleCopyCommand: Failed to send envelope: %v", err)
			}
			numEnvelopes++
		}

		// Check if we've seen the final element
		if isFinal {
			e.log.Debugf("handleCopyCommand: Found final element in box %x", boxID[:])
			sawFinal = true
		}
	}

	// Verify all data was consumed
	if decoder.Remaining() > 0 {
		e.log.Warningf("handleCopyCommand: %d bytes remaining in decoder buffer after processing", decoder.Remaining())
	}

	// Write tombstones to clean up the temporary channel
	e.writeTombstonesToTempChannel(writeCap, boxIDList)

	e.log.Debugf("handleCopyCommand: Successfully processed %d envelopes from %d boxes", numEnvelopes, len(boxIDList))

	// Return success
	return &pigeonhole.CourierQueryReply{
		ReplyType: 1, // 1 = copy_command_reply
		CopyCommandReply: &pigeonhole.CopyCommandReply{
			ErrorCode: 0, // Success
		},
	}
}

// readNextBox reads a single box from the replicas, decrypts it, and returns the raw payload.
// The payload is a serialized CopyStreamElement which will be parsed by the envelope decoder.
func (e *Courier) readNextBox(reader *bacap.StatefulReader, boxID *[bacap.BoxIDSize]byte) ([]byte, error) {
	// Read the box directly from shard replicas (not intermediate replicas)
	// This is used by the copy command which needs to read from where data is actually stored
	replicaReadReply, err := e.readBoxFromShardReplicas(boxID)
	if err != nil {
		return nil, err
	}

	// Decrypt the box to get the padded data
	sig := [bacap.SignatureSize]byte{}
	copy(sig[:], replicaReadReply.Signature[:])
	decryptedPadded, err := reader.DecryptNext(constants.PIGEONHOLE_CTX, *boxID, replicaReadReply.Payload, sig)
	if err != nil {
		e.log.Errorf("readNextBox: Failed to decrypt box %x: %v", boxID[:8], err)
		return nil, err
	}

	// Extract the actual payload from the padded data
	decryptedPayload, err := pigeonhole.ExtractMessageFromPaddedPayload(decryptedPadded)
	if err != nil {
		e.log.Errorf("readNextBox: Failed to extract payload from padded data: %v", err)
		return nil, err
	}

	// Return the raw payload (a serialized CopyStreamElement)
	return decryptedPayload, nil
}

// readBoxFromShardReplicas reads a box directly from the shard replicas where the data is stored.
// Unlike readBoxFromReplicas which uses intermediate replicas for privacy, this method
// reads directly from the shards for use by the courier's copy command.
func (e *Courier) readBoxFromShardReplicas(boxID *[bacap.BoxIDSize]byte) (*pigeonhole.ReplicaReadReply, error) {
	e.log.Debugf("readBoxFromShardReplicas: Reading box %x", boxID[:8])

	// Get PKI document
	doc := e.server.PKI.PKIDocument()
	if doc == nil {
		return nil, fmt.Errorf("PKI document is nil")
	}

	// Get shard replicas for this BoxID (the actual replicas where data is stored)
	shards, err := replicaCommon.GetShards(boxID, doc)
	if err != nil {
		return nil, fmt.Errorf("failed to get shards: %w", err)
	}
	if len(shards) == 0 {
		return nil, fmt.Errorf("no shards available for box")
	}

	// Get the current replica epoch for envelope key lookup
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()

	// Get envelope public keys for the shard replicas
	replicaPubKeys := make([]nike.PublicKey, len(shards))
	replicaIDs := make([]uint8, len(shards))
	for i, shard := range shards {
		replicaIDs[i] = shard.ReplicaID
		keyBytes, exists := shard.EnvelopeKeys[replicaEpoch]
		if !exists {
			return nil, fmt.Errorf("no envelope key found for shard replica %d at epoch %d", shard.ReplicaID, replicaEpoch)
		}
		if len(keyBytes) == 0 {
			return nil, fmt.Errorf("empty envelope key for shard replica %d at epoch %d", shard.ReplicaID, replicaEpoch)
		}
		pubKey, err := replicaCommon.NikeScheme.UnmarshalBinaryPublicKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal key for shard replica %d: %w", shard.ReplicaID, err)
		}
		replicaPubKeys[i] = pubKey
	}

	// Create ReplicaRead request
	readMsg := &pigeonhole.ReplicaRead{
		BoxID: *boxID,
	}
	innerMsg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 0, // 0 = read
		ReadMsg:     readMsg,
	}

	// Encrypt using MKEM with shard replica public keys
	mkemScheme := mkem.NewScheme(e.envelopeScheme)
	mkemPrivateKey, mkemCiphertext := mkemScheme.Encapsulate(replicaPubKeys, innerMsg.Bytes())
	mkemPublicKey := mkemPrivateKey.Public()

	// Create ReplicaMessage command
	query := &commands.ReplicaMessage{
		Cmds:               e.cmds,
		PigeonholeGeometry: e.pigeonholeGeo,
		Scheme:             e.envelopeScheme,
		SenderEPubKey:      mkemPublicKey.Bytes(),
		DEK:                mkemCiphertext.DEKCiphertexts[0],
		Ciphertext:         mkemCiphertext.Envelope,
	}

	// Calculate envelope hash for cache lookup
	envHash := query.EnvelopeHash()

	// Create channel for reply
	e.copyCacheLock.Lock()
	e.copyCache[*envHash] = make(chan *commands.ReplicaMessageReply, 1)
	e.copyCacheLock.Unlock()

	// Send directly to the first shard replica (not an intermediate replica)
	if err := e.server.SendMessage(replicaIDs[0], query); err != nil {
		e.copyCacheLock.Lock()
		delete(e.copyCache, *envHash)
		e.copyCacheLock.Unlock()
		return nil, fmt.Errorf("failed to send message to shard replica: %w", err)
	}

	// Wait for reply
	reply := <-e.copyCache[*envHash]

	// Clean up cache
	e.copyCacheLock.Lock()
	delete(e.copyCache, *envHash)
	e.copyCacheLock.Unlock()

	// Check for errors
	if reply.ErrorCode != 0 {
		return nil, fmt.Errorf("shard replica returned error code: %d", reply.ErrorCode)
	}

	// Decrypt the reply
	rawPlaintext, err := mkemScheme.DecryptEnvelope(mkemPrivateKey, replicaPubKeys[0], reply.EnvelopeReply)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt envelope reply: %w", err)
	}

	// Parse the inner message
	replyInnerMsg, err := pigeonhole.ParseReplicaMessageReplyInnerMessage(rawPlaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to parse inner message: %w", err)
	}

	// Extract ReplicaReadReply
	if replyInnerMsg.ReadReply == nil {
		return nil, fmt.Errorf("reply does not contain ReplicaReadReply")
	}

	return replyInnerMsg.ReadReply, nil
}

// writeTombstonesToTempChannel writes tombstones to clean up the temporary channel
func (e *Courier) writeTombstonesToTempChannel(writeCap *bacap.WriteCap, boxIDs [][bacap.BoxIDSize]byte) {
	e.log.Debugf("writeTombstonesToTempChannel: Writing %d tombstones", len(boxIDs))

	// Create StatefulWriter from WriteCap
	writer, err := bacap.NewStatefulWriter(writeCap, constants.PIGEONHOLE_CTX)
	if err != nil {
		e.log.Errorf("writeTombstonesToTempChannel: Failed to create StatefulWriter: %v", err)
		return
	}

	// Get PKI document for replica selection
	doc := e.server.PKI.PKIDocument()
	if doc == nil {
		e.log.Errorf("writeTombstonesToTempChannel: PKI document is nil")
		return
	}

	// Write tombstones for each box
	for i, boxID := range boxIDs {
		// Create properly padded tombstone payload (empty message padded to required size)
		// This ensures tombstones are indistinguishable from regular writes to prevent traffic analysis
		paddedPayload, err := pigeonhole.CreatePaddedPayload([]byte{}, e.pigeonholeGeo.PaddedPayloadLength())
		if err != nil {
			e.log.Errorf("writeTombstonesToTempChannel: Failed to create padded tombstone %d: %v", i, err)
			continue
		}

		// Encrypt and sign the tombstone
		encBoxID, ciphertext, sig, err := writer.EncryptNext(paddedPayload)
		if err != nil {
			e.log.Errorf("writeTombstonesToTempChannel: Failed to encrypt tombstone %d: %v", i, err)
			continue
		}

		// Verify the BoxID matches
		if encBoxID != boxID {
			e.log.Errorf("writeTombstonesToTempChannel: BoxID mismatch for tombstone %d", i)
			continue
		}

		// Get the actual storage shard replicas for this box (not intermediates)
		shards, err := replicaCommon.GetShards(&boxID, doc)
		if err != nil {
			e.log.Errorf("writeTombstonesToTempChannel: Failed to get shards for box %d: %v", i, err)
			continue
		}
		if len(shards) != 2 {
			e.log.Errorf("writeTombstonesToTempChannel: Expected 2 shards, got %d for box %d", len(shards), i)
			continue
		}

		// Get replica IDs and public keys
		replicaEpoch, _, _ := replicaCommon.ReplicaNow()
		replicaIDs := [2]uint8{shards[0].ReplicaID, shards[1].ReplicaID}
		replicaPubKeys := make([]nike.PublicKey, 2)
		for j, shard := range shards {
			keyBytes, exists := shard.EnvelopeKeys[replicaEpoch]
			if !exists {
				e.log.Errorf("writeTombstonesToTempChannel: No envelope key for replica %d at epoch %d", shard.ReplicaID, replicaEpoch)
				continue
			}
			replicaPubKeys[j], err = e.envelopeScheme.UnmarshalBinaryPublicKey(keyBytes)
			if err != nil {
				e.log.Errorf("writeTombstonesToTempChannel: Failed to unmarshal key for replica %d: %v", shard.ReplicaID, err)
				continue
			}
		}

		// Create ReplicaWrite with the tombstone
		sigArray := [bacap.SignatureSize]byte{}
		copy(sigArray[:], sig)

		writeMsg := &pigeonhole.ReplicaWrite{
			BoxID:      boxID,
			Signature:  sigArray,
			PayloadLen: uint32(len(ciphertext)),
			Payload:    ciphertext,
		}

		// Wrap in ReplicaInnerMessage
		innerMsg := &pigeonhole.ReplicaInnerMessage{
			MessageType: 1, // 1 = write
			WriteMsg:    writeMsg,
		}

		// Encrypt using MKEM for both replicas
		mkemScheme := mkem.NewScheme(e.envelopeScheme)
		mkemPrivateKey, mkemCiphertext := mkemScheme.Encapsulate(replicaPubKeys, innerMsg.Bytes())
		mkemPublicKey := mkemPrivateKey.Public()

		// Send directly to each storage replica
		for j, replicaID := range replicaIDs {
			query := &commands.ReplicaMessage{
				Cmds:               e.cmds,
				PigeonholeGeometry: e.pigeonholeGeo,
				Scheme:             e.envelopeScheme,
				SenderEPubKey:      mkemPublicKey.Bytes(),
				DEK:                mkemCiphertext.DEKCiphertexts[j],
				Ciphertext:         mkemCiphertext.Envelope,
			}

			// Send directly to storage replica
			if err := e.server.SendMessage(replicaID, query); err != nil {
				e.log.Errorf("writeTombstonesToTempChannel: Failed to send tombstone %d to replica %d: %v", i, replicaID, err)
				continue
			}

			e.log.Debugf("writeTombstonesToTempChannel: Sent tombstone %d/%d for box %x to replica %d", i+1, len(boxIDs), boxID[:8], replicaID)
		}
	}

	e.log.Debugf("writeTombstonesToTempChannel: Finished writing %d tombstones", len(boxIDs))
}

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
