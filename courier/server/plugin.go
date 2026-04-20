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

	"github.com/katzenpost/katzenpost/client/constants"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/courier/server/instrument"
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
	CreatedAt            time.Time
	QueryType            uint8
	IntermediateReplicas [2]uint8 // Store the replica IDs that were contacted
	EnvelopeReplies      [2]*commands.ReplicaMessageReply
}

// CopyCommandState tracks the state of a copy command for idempotency.
// This allows copy commands to be safely retried via ARQ without duplicating work.
type CopyCommandState struct {
	InProgress  bool
	Done        chan struct{}                 // Closed when the copy command completes
	Result      *pigeonhole.CourierQueryReply // Cached result (nil if still in progress)
	CompletedAt time.Time                     // When the copy command completed
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

	// Copy command deduplication cache — tracks in-progress and
	// completed copy commands. The client daemon polls the same
	// WriteCap to learn the terminal Status; this map is the source of
	// truth for those polls.
	copyDedupCacheLock sync.RWMutex
	copyDedupCache     map[[hash.HashSize]byte]*CopyCommandState

	// processCopyCommandFn is the worker that performs the actual Copy
	// work in a background goroutine. Defaults to
	// (*Courier).processCopyCommand in production; tests swap it for a
	// fake that doesn't need real replica connectivity.
	processCopyCommandFn func(copyCmd *pigeonhole.CopyCommand) *pigeonhole.CourierQueryReply
}

// CopyDedupCacheTTL bounds how long a completed Copy command's status
// stays retrievable by the client via polling. Long enough to cover a
// reconnecting client that missed earlier polls, short enough that the
// cache stays bounded in memory.
const CopyDedupCacheTTL = 30 * time.Minute

const (
	// maxCopyReadTransientAttempts is how many times a single shard
	// replica is re-queried on a temporary error (per the classifier)
	// before the read path fails over to the shard peer.
	maxCopyReadTransientAttempts = 3

	// copyReadReplyTimeout bounds how long the courier waits for a
	// reply from one shard replica during a Copy read. A stuck replica
	// cannot pin the background Copy goroutine for longer than this.
	copyReadReplyTimeout = 10 * time.Second

	// maxCopyWriteAttempts is how many times the courier tries to
	// dispatch a single copy-stream envelope to its intermediate
	// replicas before aborting the Copy command. Write-side failover
	// between shard peers is not available — the intermediate replicas
	// are baked into the client's MKEM envelope.
	maxCopyWriteAttempts = 5

	// copyWriteReplyTimeout bounds how long the courier waits for
	// both intermediate-replica replies after dispatching a Copy
	// envelope. One unresponsive intermediate cannot pin the Copy
	// goroutine; if only one reply arrives within this window, it is
	// treated as the authoritative outcome.
	copyWriteReplyTimeout = 15 * time.Second

	// copyBackoffBase is the base backoff between attempts for both
	// read and write retry loops; each attempt doubles up to
	// copyBackoffCap.
	copyBackoffBase = 500 * time.Millisecond
	copyBackoffCap  = 5 * time.Second
)

// copyAttemptBackoff returns the sleep between attempt n and attempt
// n+1 within the same loop, capped at copyBackoffCap.
func copyAttemptBackoff(attempt int) time.Duration {
	shift := attempt
	if shift > 8 {
		shift = 8
	}
	d := copyBackoffBase * time.Duration(1<<uint(shift))
	if d > copyBackoffCap {
		d = copyBackoffCap
	}
	return d
}

// copySucceededReply is the terminal reply for a successful Copy.
func copySucceededReply() *pigeonhole.CourierQueryReply {
	return &pigeonhole.CourierQueryReply{
		ReplyType: 1,
		CopyCommandReply: &pigeonhole.CopyCommandReply{
			Status: pigeonhole.CopyStatusSucceeded,
		},
	}
}

// copyFailedReply is the terminal reply for an aborted Copy. replicaErr
// is the replica ErrorCode that triggered the abort (0 if the failure
// was purely on the courier side). failedEnvelopeIndex is the 1-based
// sequential position in the copy stream that could not be completed
// — successfully_processed_envelopes + 1. 0 if not applicable.
func copyFailedReply(replicaErr uint8, failedEnvelopeIndex uint64) *pigeonhole.CourierQueryReply {
	return &pigeonhole.CourierQueryReply{
		ReplyType: 1,
		CopyCommandReply: &pigeonhole.CopyCommandReply{
			Status:              pigeonhole.CopyStatusFailed,
			ErrorCode:           replicaErr,
			FailedEnvelopeIndex: failedEnvelopeIndex,
		},
	}
}

// DedupCacheTTL bounds how long a CourierBookKeeping entry stays in
// dedupCache. Long enough to cover an active ARQ retry cycle for a single
// envelope, short enough that dedupCache size stays bounded under load.
const DedupCacheTTL = 5 * time.Minute

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
		dedupCache:     make(map[[hash.HashSize]byte]*CourierBookKeeping),
		copyCache:      make(map[[hash.HashSize]byte]chan *commands.ReplicaMessageReply),
		copyDedupCache: make(map[[hash.HashSize]byte]*CopyCommandState),
	}
	courier.processCopyCommandFn = courier.processCopyCommand
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
	e.log.Debugf("CacheReply: found existing cache entry for envelope hash %x", reply.EnvelopeHash)

	replyIndex := e.findReplicaIndex(entry, reply.ReplicaID)
	if replyIndex >= 0 {
		e.storeOrReplaceReply(entry, reply, replyIndex)
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

// storeOrReplaceReply stores the reply, replacing any existing error reply with a successful one
func (e *Courier) storeOrReplaceReply(entry *CourierBookKeeping, reply *commands.ReplicaMessageReply, replyIndex int) {
	existing := entry.EnvelopeReplies[replyIndex]
	if existing == nil {
		// No existing reply, store the new one
		e.log.Infof("CacheReply: storing reply from replica %d at IntermediateReplicas index %d", reply.ReplicaID, replyIndex)
		entry.EnvelopeReplies[replyIndex] = reply
	} else if existing.ErrorCode != 0 {
		// Overwrite cached errors with newer replies. Errors may be transient
		// (e.g. BoxIDNotFound that resolves when data propagates).
		e.log.Infof("CacheReply: replacing cached error (err=%d) with new reply (err=%d) from replica %d at index %d",
			existing.ErrorCode, reply.ErrorCode, reply.ReplicaID, replyIndex)
		entry.EnvelopeReplies[replyIndex] = reply
	} else {
		e.log.Debugf("CacheReply: reply from replica %d already cached, ignoring duplicate", reply.ReplicaID)
	}
}

// pruneDedupCacheLocked removes entries whose age (now - CreatedAt) is
// strictly greater than ttl. Returns the number of entries removed.
// The caller MUST hold e.dedupCacheLock.Lock().
func (e *Courier) pruneDedupCacheLocked(now time.Time, ttl time.Duration) int {
	pruned := 0
	for key, entry := range e.dedupCache {
		if now.Sub(entry.CreatedAt) > ttl {
			delete(e.dedupCache, key)
			pruned++
		}
	}
	return pruned
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
	// The actual response with data will come later via CacheReply when replicas respond
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

	// Bound ReplyIndex to the size of EnvelopeReplies. The field is
	// client-supplied, and anything outside [0, 1] would panic the
	// courier goroutine on the indexed lookups below.
	if courierMessage.ReplyIndex > 1 {
		e.log.Warningf("handleOldMessage: rejecting out-of-range ReplyIndex=%d for envelope hash %x", courierMessage.ReplyIndex, envHash)
		return e.createEnvelopeErrorReply(envHash, pigeonhole.EnvelopeErrorInvalidEnvelope, 0)
	}

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
		e.log.Debugf("Found reply [len:%d err:%d] at requested index %d for %v", len(payload), entry.ErrorCode, courierMessage.ReplyIndex, envHash)
		// If the payload at requested index is empty, try the other index
		if len(payload) == 0 && cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex^1] != nil {
			oentry := cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex^1]
			if len(oentry.EnvelopeReply) > 0 {
				e.log.Debugf("entry at idx %v is empty; using other index with [len:%d err:%d]", courierMessage.ReplyIndex, len(oentry.EnvelopeReply), oentry.ErrorCode)
				courierMessage.ReplyIndex = courierMessage.ReplyIndex ^ 1
				payload = oentry.EnvelopeReply
			}
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
	if len(payload) > 0 {
		replyType = pigeonhole.ReplyTypePayload // Has actual data (including error responses)
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
	instrument.MessagesReceived()

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
		reply := e.cacheHandleCourierEnvelope(courierQuery.QueryType, courierQuery.Envelope)

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

func (e *Courier) cacheHandleCourierEnvelope(queryType uint8, courierMessage *pigeonhole.CourierEnvelope) *pigeonhole.CourierQueryReply {
	envHash := courierMessage.EnvelopeHash()

	// Epoch validation happens before any cache work: an envelope whose
	// replica epoch is outside the tolerance window cannot decapsulate
	// at any replica we can reach (see specs/pigeonhole.md "Epoch
	// tolerance for CourierEnvelope"), so there's nothing productive to
	// cache and we shouldn't spend a dispatch on it.
	currentReplicaEpoch, _, _ := replicaCommon.ReplicaNow()
	if !isEnvelopeEpochAcceptable(courierMessage.Epoch, currentReplicaEpoch) {
		e.log.Warningf("cacheHandleCourierEnvelope: rejecting envelope %x with epoch %d (current replica epoch %d)",
			envHash[:8], courierMessage.Epoch, currentReplicaEpoch)
		return e.createEnvelopeErrorReply(envHash, pigeonhole.EnvelopeErrorInvalidEpoch, courierMessage.ReplyIndex)
	}

	e.dedupCacheLock.RLock()
	cacheEntry, ok := e.dedupCache[*envHash]
	e.dedupCacheLock.RUnlock()

	switch {
	case ok:
		// If the cached entry contains only read errors (e.g. BoxIDNotFound), trigger an
		// async re-dispatch to the replicas so the cache gets refreshed for the next client
		// retry. We still return the cached error immediately via handleOldMessage so that
		// NoRetry clients receive the error and stop, while Retry clients' next request will
		// find either success or a fresh BoxIDNotFound in the cache.
		if e.cacheEntryHasOnlyErrors(cacheEntry) {
			e.log.Debugf("OnCommand: Cached entry for %x has read errors, triggering async re-dispatch", envHash)
			go func() {
				if err := e.propagateQueryToReplicas(courierMessage); err != nil {
					e.log.Errorf("OnCommand: async re-dispatch for %x failed: %s", envHash, err)
				}
			}()
		}
		e.log.Debugf("OnCommand: Found cached entry for envelope hash %x, calling handleOldMessage", envHash)
		return e.handleOldMessage(cacheEntry, envHash, courierMessage)
	case !ok:
		e.log.Errorf("OnCommand: No cached entry for envelope hash %x, calling handleNewMessage", envHash)
		e.dedupCacheLock.Lock()
		e.pruneDedupCacheLocked(time.Now(), DedupCacheTTL)
		currentEpoch := e.getCurrentEpoch()
		e.dedupCache[*envHash] = &CourierBookKeeping{
			Epoch:                currentEpoch,
			CreatedAt:            time.Now(),
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

// cacheEntryHasOnlyErrors returns true when every replica reply that has arrived so far
// has a non-zero error code. It returns false when at least one reply is absent
// (still in flight) or successful.
//
// When true, the courier triggers an async re-dispatch to replicas so the cache
// gets refreshed. This handles transient errors like BoxIDNotFound that resolve
// when data propagates.
func (e *Courier) cacheEntryHasOnlyErrors(entry *CourierBookKeeping) bool {
	if entry == nil {
		return false
	}
	hasAny := false
	for _, reply := range entry.EnvelopeReplies {
		if reply == nil {
			continue
		}
		if reply.ErrorCode == 0 {
			return false // at least one successful reply exists
		}
		hasAny = true
	}
	return hasAny
}

// handleCopyCommand is the dispatch layer for an incoming Copy command.
// It is non-blocking: the actual work of reading the temp stream,
// decoding envelopes, dispatching them to replicas, and tombstoning
// the temp stream runs in a background goroutine.
//
// The client drives completion by polling with the same WriteCap.
// Replies carry a Status field:
//
//   - InProgress: courier is still working (or just received the
//     command). Client should keep polling.
//   - Succeeded:  all copy tasks completed.
//   - Failed:     processing aborted; CopyCommandReply.ErrorCode and
//     FailedEnvelopeIndex identify the specific replica error and the
//     1-based sequential position in the copy stream.
//
// Dedup is by blake2b hash of the serialized WriteCap. Terminal
// results stay in copyDedupCache for CopyDedupCacheTTL so a client
// that reconnects or polls late still sees the outcome.
func (e *Courier) handleCopyCommand(copyCmd *pigeonhole.CopyCommand) *pigeonhole.CourierQueryReply {
	e.log.Debugf("handleCopyCommand: Processing copy command with WriteCap length %d", copyCmd.WriteCapLen)

	copyKey := hash.Sum256(copyCmd.WriteCap)

	e.copyDedupCacheLock.Lock()
	state, exists := e.copyDedupCache[copyKey]
	if exists {
		if state.InProgress {
			e.copyDedupCacheLock.Unlock()
			e.log.Debugf("handleCopyCommand: %x still in progress, returning InProgress", copyKey[:8])
			return inProgressReply()
		}
		// Completed: return cached result if within TTL, else drop and
		// reprocess.
		if time.Since(state.CompletedAt) < CopyDedupCacheTTL {
			result := state.Result
			e.copyDedupCacheLock.Unlock()
			e.log.Debugf("handleCopyCommand: %x returning cached terminal status", copyKey[:8])
			return result
		}
		e.log.Debugf("handleCopyCommand: cached result for %x expired, reprocessing", copyKey[:8])
		delete(e.copyDedupCache, copyKey)
	}

	// New (or TTL-expired) copy: mark InProgress, spawn worker, ACK.
	state = &CopyCommandState{
		InProgress: true,
		Done:       make(chan struct{}),
	}
	e.copyDedupCache[copyKey] = state
	e.copyDedupCacheLock.Unlock()

	go e.runCopyCommand(copyCmd, copyKey, state)

	return inProgressReply()
}

// runCopyCommand executes the Copy work in the background and stores
// the terminal reply in copyDedupCache so later polls can return it.
// It is the sole writer of the transition from InProgress=true to
// InProgress=false for a given copyKey.
func (e *Courier) runCopyCommand(copyCmd *pigeonhole.CopyCommand, copyKey [hash.HashSize]byte, state *CopyCommandState) {
	defer func() {
		if r := recover(); r != nil {
			e.log.Errorf("runCopyCommand: panic for %x: %v", copyKey[:8], r)
			e.copyDedupCacheLock.Lock()
			state.InProgress = false
			state.Result = &pigeonhole.CourierQueryReply{
				ReplyType: 1,
				CopyCommandReply: &pigeonhole.CopyCommandReply{
					Status: pigeonhole.CopyStatusFailed,
				},
			}
			state.CompletedAt = time.Now()
			close(state.Done)
			e.copyDedupCacheLock.Unlock()
		}
	}()

	result := e.processCopyCommandFn(copyCmd)

	e.copyDedupCacheLock.Lock()
	state.InProgress = false
	state.Result = result
	state.CompletedAt = time.Now()
	close(state.Done)
	e.copyDedupCacheLock.Unlock()
	e.log.Debugf("runCopyCommand: %x finished with Status=%d", copyKey[:8], result.CopyCommandReply.Status)
}

// inProgressReply is the empty-ACK-equivalent reply the courier uses to
// acknowledge receipt of a Copy command (and to answer polls while
// processing continues).
func inProgressReply() *pigeonhole.CourierQueryReply {
	return &pigeonhole.CourierQueryReply{
		ReplyType: 1,
		CopyCommandReply: &pigeonhole.CopyCommandReply{
			Status: pigeonhole.CopyStatusInProgress,
		},
	}
}

// processCopyCommand does the actual work of processing a copy command.
// This is separated from handleCopyCommand to support the deduplication logic.
func (e *Courier) processCopyCommand(copyCmd *pigeonhole.CopyCommand) *pigeonhole.CourierQueryReply {
	writeCap, err := bacap.NewWriteCapFromBytes(copyCmd.WriteCap)
	if err != nil {
		e.log.Errorf("processCopyCommand: deserialize WriteCap: %v", err)
		return copyFailedReply(0, 0)
	}
	readCap := writeCap.ReadCap()
	reader, err := bacap.NewStatefulReader(readCap, constants.PIGEONHOLE_CTX)
	if err != nil {
		e.log.Errorf("processCopyCommand: NewStatefulReader: %v", err)
		return copyFailedReply(0, 0)
	}

	// envelopesProcessed is the count of copy-stream envelopes that have
	// been successfully dispatched to their intermediate replicas. When
	// a later step fails, the reported FailedEnvelopeIndex is
	// envelopesProcessed + 1 — the 1-based position of the next
	// envelope the courier would have handled.
	var boxIDList [][bacap.BoxIDSize]byte
	decoder := pigeonhole.NewCopyStreamEnvelopeDecoder(e.pigeonholeGeo)
	envelopesProcessed := uint64(0)
	sawFinal := false

	for !sawFinal {
		boxID, err := reader.NextBoxID()
		if err != nil {
			e.log.Errorf("processCopyCommand: NextBoxID: %v", err)
			return copyFailedReply(0, envelopesProcessed+1)
		}
		boxIDList = append(boxIDList, *boxID)

		boxPlaintext, replicaCode, err := e.readNextBox(reader, boxID)
		if err != nil {
			e.log.Errorf("processCopyCommand: readNextBox box %x: replicaCode=%d err=%v", boxID[:8], replicaCode, err)
			return copyFailedReply(replicaCode, envelopesProcessed+1)
		}

		decoder.AddBoxData(boxPlaintext)
		envelopes, isFinal, err := decoder.DecodeEnvelopes()
		if err != nil {
			e.log.Errorf("processCopyCommand: DecodeEnvelopes: %v", err)
			return copyFailedReply(0, envelopesProcessed+1)
		}

		for _, envelope := range envelopes {
			ok, replicaErr := e.dispatchCopyEnvelope(envelope)
			if !ok {
				return copyFailedReply(replicaErr, envelopesProcessed+1)
			}
			envelopesProcessed++
		}

		if isFinal {
			e.log.Debugf("processCopyCommand: saw final element in box %x", boxID[:])
			sawFinal = true
		}
	}

	if decoder.Remaining() > 0 {
		e.log.Warningf("processCopyCommand: %d bytes remaining in decoder buffer after processing", decoder.Remaining())
	}

	// Tombstones are best-effort: we've already written the destination
	// envelopes, so an incomplete temp-stream cleanup is a cache
	// inefficiency, not a correctness failure.
	e.writeTombstonesToTempChannel(writeCap, boxIDList)

	e.log.Debugf("processCopyCommand: processed %d envelopes from %d boxes", envelopesProcessed, len(boxIDList))
	return copySucceededReply()
}

// dispatchCopyEnvelope sends one copy-stream CourierEnvelope to its
// client-chosen intermediate replicas, waits for both replies (with a
// timeout), and classifies the outcome.
//
// Return values:
//
//   - (true, 0)
//     at least one intermediate's reply indicates success; with K=2
//     shard redundancy this means the data reached a shard and the
//     Copy can continue.
//
//   - (false, replicaErrorCode)
//     both intermediates rejected the write (e.g. BoxAlreadyExists,
//     InvalidSignature) or the transport layer exhausted its attempt
//     budget. replicaErrorCode is the best signal the courier has
//     to propagate to the client. 0 means the failure was transport-
//     only (no replica reply ever arrived).
//
// No shard-level failover is available on the write path because the
// two intermediate replicas are MKEM-baked into the client's envelope.
// SendMessage failures get up to maxCopyWriteAttempts tries under
// copyAttemptBackoff before dispatch is declared terminal.
func (e *Courier) dispatchCopyEnvelope(envelope *pigeonhole.CourierEnvelope) (bool, uint8) {
	envHash := envelope.EnvelopeHash()

	for attempt := 0; attempt < maxCopyWriteAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(copyAttemptBackoff(attempt - 1))
		}

		// Buffer 2 so both intermediates can land without blocking
		// the HandleReply goroutine.
		ch := make(chan *commands.ReplicaMessageReply, 2)
		e.copyCacheLock.Lock()
		e.copyCache[*envHash] = ch
		e.copyCacheLock.Unlock()

		sendErr := e.propagateQueryToReplicas(envelope)
		if sendErr != nil {
			e.copyCacheLock.Lock()
			delete(e.copyCache, *envHash)
			e.copyCacheLock.Unlock()
			e.log.Warningf("dispatchCopyEnvelope: attempt %d SendMessage failed: %v", attempt+1, sendErr)
			continue
		}

		var replies []*commands.ReplicaMessageReply
		deadline := time.After(copyWriteReplyTimeout)
		collecting := true
		for collecting && len(replies) < 2 {
			select {
			case r := <-ch:
				replies = append(replies, r)
			case <-deadline:
				collecting = false
			}
		}

		e.copyCacheLock.Lock()
		delete(e.copyCache, *envHash)
		e.copyCacheLock.Unlock()

		if len(replies) == 0 {
			e.log.Warningf("dispatchCopyEnvelope: attempt %d timed out with no replies", attempt+1)
			continue
		}

		// K=2 redundancy: at least one success means the data is
		// stored — continue the Copy.
		bestErr := uint8(0)
		for _, r := range replies {
			if r.ErrorCode == pigeonhole.ReplicaSuccess {
				if attempt > 0 {
					e.log.Debugf("dispatchCopyEnvelope: success on attempt %d", attempt+1)
				}
				return true, 0
			}
			// Prefer BoxAlreadyExists as the reportable code — it's
			// the most diagnostic signal for the client's Copy
			// failure report.
			if r.ErrorCode == pigeonhole.ReplicaErrorBoxAlreadyExists || bestErr == 0 {
				bestErr = r.ErrorCode
			}
		}

		// Both replies are errors.
		// BoxAlreadyExists is a terminal outcome — the destination
		// box was pre-written, retrying won't change that.
		if bestErr == pigeonhole.ReplicaErrorBoxAlreadyExists {
			e.log.Warningf("dispatchCopyEnvelope: both intermediates report BoxAlreadyExists, aborting Copy")
			return false, bestErr
		}

		e.log.Warningf("dispatchCopyEnvelope: attempt %d: both replies error (best=%d), retrying", attempt+1, bestErr)
	}

	e.log.Errorf("dispatchCopyEnvelope: exhausted %d attempts, aborting Copy", maxCopyWriteAttempts)
	return false, 0
}

// readNextBox reads a single box from the shard replicas, decrypts it,
// and returns the CopyStreamElement bytes plus the replica ErrorCode
// that caused failure (0 on success). Used by the Copy command to
// walk the temp stream.
func (e *Courier) readNextBox(reader *bacap.StatefulReader, boxID *[bacap.BoxIDSize]byte) ([]byte, uint8, error) {
	replicaReadReply, replicaCode, err := e.readBoxFromShardReplicas(boxID)
	if err != nil {
		return nil, replicaCode, err
	}

	sig := [bacap.SignatureSize]byte{}
	copy(sig[:], replicaReadReply.Signature[:])
	decryptedPadded, err := reader.DecryptNext(constants.PIGEONHOLE_CTX, *boxID, replicaReadReply.Payload, sig)
	if err != nil {
		e.log.Errorf("readNextBox: Failed to decrypt box %x: %v", boxID[:8], err)
		return nil, 0, err
	}

	decryptedPayload, err := pigeonhole.ExtractMessageFromPaddedPayload(decryptedPadded)
	if err != nil {
		e.log.Errorf("readNextBox: Failed to extract payload from padded data: %v", err)
		return nil, 0, err
	}

	return decryptedPayload, 0, nil
}

// readBoxFromShardReplicas reads a temp-stream box directly from its
// shard replicas, iterating each shard with a bounded number of
// transient retries before failing over to the shard peer. Returns the
// last observed replica ErrorCode (for a Failed CopyCommandReply) and
// a non-nil error if every shard exhausted.
//
// Every attempt uses a fresh ephemeral MKEM keypair so its EnvelopeHash
// is unique in the copyCache reply-demux table.
func (e *Courier) readBoxFromShardReplicas(boxID *[bacap.BoxIDSize]byte) (*pigeonhole.ReplicaReadReply, uint8, error) {
	e.log.Debugf("readBoxFromShardReplicas: Reading box %x", boxID[:8])

	doc := e.server.PKI.PKIDocument()
	if doc == nil {
		return nil, 0, fmt.Errorf("PKI document is nil")
	}

	shards, err := replicaCommon.GetShards(boxID, doc)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get shards: %w", err)
	}
	if len(shards) == 0 {
		return nil, 0, fmt.Errorf("no shards available for box")
	}

	replicaEpoch, _, _ := replicaCommon.ReplicaNow()

	var lastReplicaCode uint8
	var lastErr error

	for _, shard := range shards {
		keyBytes, exists := shard.EnvelopeKeys[replicaEpoch]
		if !exists || len(keyBytes) == 0 {
			lastErr = fmt.Errorf("no envelope key for shard %d at epoch %d", shard.ReplicaID, replicaEpoch)
			continue
		}
		shardPubKey, err := replicaCommon.NikeScheme.UnmarshalBinaryPublicKey(keyBytes)
		if err != nil {
			lastErr = fmt.Errorf("unmarshal shard %d key: %w", shard.ReplicaID, err)
			continue
		}

		failover := false
		for attempt := 0; attempt < maxCopyReadTransientAttempts && !failover; attempt++ {
			if attempt > 0 {
				time.Sleep(copyAttemptBackoff(attempt - 1))
			}
			reply, replicaCode, attemptErr := e.tryReadFromShardReplica(boxID, shard, shardPubKey)
			if attemptErr != nil {
				// Transport/crypto hiccup — retry same shard under
				// the transient-attempts budget.
				lastErr = attemptErr
				e.log.Debugf("readBoxFromShardReplicas: shard %d attempt %d transport error: %v", shard.ReplicaID, attempt+1, attemptErr)
				continue
			}
			if replicaCode == pigeonhole.ReplicaSuccess {
				return reply, 0, nil
			}
			lastReplicaCode = replicaCode
			switch classifyReplicaErrorForCopyRead(replicaCode) {
			case replicaErrorTemporary:
				e.log.Debugf("readBoxFromShardReplicas: shard %d attempt %d temporary replica error %d", shard.ReplicaID, attempt+1, replicaCode)
			case replicaErrorPermanent:
				e.log.Debugf("readBoxFromShardReplicas: shard %d permanent replica error %d, failing over", shard.ReplicaID, replicaCode)
				failover = true
			}
		}
	}

	if lastErr == nil {
		if lastReplicaCode != 0 {
			lastErr = fmt.Errorf("all shard replicas exhausted (last replica code: %d)", lastReplicaCode)
		} else {
			lastErr = fmt.Errorf("all shard replicas exhausted")
		}
	}
	return nil, lastReplicaCode, lastErr
}

// tryReadFromShardReplica performs a single MKEM-encrypted read to one
// specific shard replica, waits for the reply with a timeout, and
// returns the parsed ReplicaReadReply plus the replica's ErrorCode
// (0 on success). A non-nil error signals a transport / crypto /
// timeout failure — the caller should retry under its transient budget.
func (e *Courier) tryReadFromShardReplica(
	boxID *[bacap.BoxIDSize]byte,
	shard *cpki.ReplicaDescriptor,
	shardPubKey nike.PublicKey,
) (*pigeonhole.ReplicaReadReply, uint8, error) {
	readMsg := &pigeonhole.ReplicaRead{BoxID: *boxID}
	innerMsg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 0,
		ReadMsg:     readMsg,
	}

	mkemScheme := mkem.NewScheme(e.envelopeScheme)
	mkemPrivateKey, mkemCiphertext := mkemScheme.Encapsulate([]nike.PublicKey{shardPubKey}, innerMsg.Bytes())

	query := &commands.ReplicaMessage{
		Cmds:               e.cmds,
		PigeonholeGeometry: e.pigeonholeGeo,
		Scheme:             e.envelopeScheme,
		SenderEPubKey:      mkemPrivateKey.Public().Bytes(),
		DEK:                mkemCiphertext.DEKCiphertexts[0],
		Ciphertext:         mkemCiphertext.Envelope,
	}
	envHash := query.EnvelopeHash()

	ch := make(chan *commands.ReplicaMessageReply, 1)
	e.copyCacheLock.Lock()
	e.copyCache[*envHash] = ch
	e.copyCacheLock.Unlock()
	defer func() {
		e.copyCacheLock.Lock()
		delete(e.copyCache, *envHash)
		e.copyCacheLock.Unlock()
	}()

	if err := e.server.SendMessage(shard.ReplicaID, query); err != nil {
		return nil, 0, fmt.Errorf("SendMessage to shard %d: %w", shard.ReplicaID, err)
	}

	var reply *commands.ReplicaMessageReply
	select {
	case reply = <-ch:
	case <-time.After(copyReadReplyTimeout):
		return nil, 0, fmt.Errorf("shard %d: reply timeout after %v", shard.ReplicaID, copyReadReplyTimeout)
	}

	if reply.ErrorCode != pigeonhole.ReplicaSuccess {
		return nil, reply.ErrorCode, nil
	}

	raw, err := mkemScheme.DecryptEnvelope(mkemPrivateKey, shardPubKey, reply.EnvelopeReply)
	if err != nil {
		return nil, 0, fmt.Errorf("shard %d: decrypt envelope: %w", shard.ReplicaID, err)
	}
	replyInner, err := pigeonhole.ParseReplicaMessageReplyInnerMessage(raw)
	if err != nil {
		return nil, 0, fmt.Errorf("shard %d: parse inner: %w", shard.ReplicaID, err)
	}
	if replyInner.ReadReply == nil {
		return nil, 0, fmt.Errorf("shard %d: reply is not a ReadReply", shard.ReplicaID)
	}
	return replyInner.ReadReply, 0, nil
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

		// Collect the shards whose envelope pubkey is usable. With K=2
		// redundancy a single good key is sufficient — the peer shard
		// picks the tombstone up via replica-to-replica replication.
		// If BOTH keys are unusable, skip this box.
		replicaEpoch, _, _ := replicaCommon.ReplicaNow()
		usableReplicaIDs := make([]uint8, 0, 2)
		usablePubKeys := make([]nike.PublicKey, 0, 2)
		for _, shard := range shards {
			keyBytes, exists := shard.EnvelopeKeys[replicaEpoch]
			if !exists {
				e.log.Warningf("writeTombstonesToTempChannel: No envelope key for replica %d at epoch %d", shard.ReplicaID, replicaEpoch)
				continue
			}
			pk, err := e.envelopeScheme.UnmarshalBinaryPublicKey(keyBytes)
			if err != nil {
				e.log.Warningf("writeTombstonesToTempChannel: Failed to unmarshal key for replica %d: %v", shard.ReplicaID, err)
				continue
			}
			usableReplicaIDs = append(usableReplicaIDs, shard.ReplicaID)
			usablePubKeys = append(usablePubKeys, pk)
		}
		if len(usablePubKeys) == 0 {
			e.log.Errorf("writeTombstonesToTempChannel: no usable shard keys for box %d, skipping", i)
			continue
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

		// Encrypt using MKEM for whichever shard keys we have.
		mkemScheme := mkem.NewScheme(e.envelopeScheme)
		mkemPrivateKey, mkemCiphertext := mkemScheme.Encapsulate(usablePubKeys, innerMsg.Bytes())
		mkemPublicKey := mkemPrivateKey.Public()

		// Send directly to each usable storage replica.
		for j, replicaID := range usableReplicaIDs {
			query := &commands.ReplicaMessage{
				Cmds:               e.cmds,
				PigeonholeGeometry: e.pigeonholeGeo,
				Scheme:             e.envelopeScheme,
				SenderEPubKey:      mkemPublicKey.Bytes(),
				DEK:                mkemCiphertext.DEKCiphertexts[j],
				Ciphertext:         mkemCiphertext.Envelope,
			}

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
