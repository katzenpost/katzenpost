// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/replica/common"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

// CourierBookKeeping is used for:
// 1. deduping writes
// 2. deduping reads
// 3. caching replica replies
type CourierBookKeeping struct {
	Epoch                uint64
	IntermediateReplicas [2]uint8 // Store the replica IDs that were contacted
	EnvelopeReplies      [2]*commands.ReplicaMessageReply
}

// Courier handles the CBOR plugin interface for our courier service.
type Courier struct {
	write  func(cborplugin.Command)
	server *Server
	log    *logging.Logger

	cmds           *commands.Commands
	geo            *geo.Geometry
	envelopeScheme nike.Scheme

	dedupCacheLock sync.RWMutex
	dedupCache     map[[hash.HashSize]byte]*CourierBookKeeping
}

// NewCourier returns a new Courier type.
func NewCourier(s *Server, cmds *commands.Commands, scheme nike.Scheme) *Courier {

	courier := &Courier{
		server:         s,
		log:            s.logBackend.GetLogger("courier"),
		cmds:           cmds,
		geo:            s.cfg.SphinxGeometry,
		envelopeScheme: scheme,
		dedupCache:     make(map[[hash.HashSize]byte]*CourierBookKeeping),
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

func (e *Courier) CacheReply(reply *commands.ReplicaMessageReply) {
	e.log.Debugf("CacheReply called with envelope hash: %x", reply.EnvelopeHash)

	if !e.validateReply(reply) {
		return
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
		e.log.Debug("CacheReply: envelope hash is nil, not caching")
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

func (e *Courier) handleNewMessage(envHash *[hash.HashSize]byte, courierMessage *common.CourierEnvelope) *common.CourierQueryReply {
	replicas := make([]*commands.ReplicaMessage, 2)

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

	envelopeReply := &common.CourierEnvelopeReply{
		EnvelopeHash: envHash,
		ReplyIndex:   0,
		Payload:      nil,
		ErrorCode:    0,
	}

	reply := &common.CourierQueryReply{
		CourierEnvelopeReply: envelopeReply,
		CopyCommandReply:     nil,
	}
	return reply
}

func (e *Courier) handleOldMessage(cacheEntry *CourierBookKeeping, envHash *[hash.HashSize]byte, courierMessage *common.CourierEnvelope) *common.CourierQueryReply {
	e.log.Debugf("handleOldMessage called for envelope hash: %x, requested ReplyIndex: %d", envHash, courierMessage.ReplyIndex)

	envelopeReply := &common.CourierEnvelopeReply{
		EnvelopeHash: envHash,
		ReplyIndex:   courierMessage.ReplyIndex,
		ErrorCode:    0,
	}

	// Check if cacheEntry is nil before accessing its fields
	if cacheEntry == nil {
		e.log.Debugf("Cache entry is nil, no replies available")
		reply := &common.CourierQueryReply{
			CourierEnvelopeReply: envelopeReply,
			CopyCommandReply:     nil,
		}
		return reply
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

	courierQuery, err := common.CourierQueryFromBytes(request.Payload)
	if err != nil {
		e.log.Debugf("Bug, failed to decode CourierQuery CBOR blob: %s", err)
		return err
	}

	// Handle CourierEnvelope if present
	if courierQuery.CourierEnvelope != nil {
		reply := e.handleCourierEnvelope(courierQuery.CourierEnvelope)

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

		reply := e.handleCopyCommand(courierQuery.CopyCommand.WriteCap)

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

func (e *Courier) handleCourierEnvelope(courierMessage *common.CourierEnvelope) *common.CourierQueryReply {
	envHash := courierMessage.EnvelopeHash()

	var reply *common.CourierQueryReply
	e.dedupCacheLock.RLock()
	cacheEntry, ok := e.dedupCache[*envHash]
	e.dedupCacheLock.RUnlock()

	if ok {
		e.log.Debugf("OnCommand: Found cached entry for envelope hash %x, calling handleOldMessage", envHash)
		reply = e.handleOldMessage(cacheEntry, envHash, courierMessage)
	} else {
		e.log.Debugf("OnCommand: No cached entry for envelope hash %x, calling handleNewMessage", envHash)
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
		reply = e.handleNewMessage(envHash, courierMessage)
	}

	return reply
}

func (e *Courier) handleCopyCommand(writeCap *bacap.BoxOwnerCap) *common.CourierQueryReply {
	// here we BACAP Boxes from the readcap which we can derive from the given writecap.
	// we don't know exactly how many Boxes but if we encounter a final Box it will have
	// content which is padded with zeros instead of the next CBOR blob.

	//readcap := writeCap.UniversalReadCap()

	// For now, return an error reply
	errorReply := &common.CourierQueryReply{
		CourierEnvelopeReply: nil,
		CopyCommandReply: &common.CopyCommandReply{
			ErrorCode: 1, // Error code 1 for not implemented
		},
	}

	return errorReply
}

func (e *Courier) RegisterConsumer(s *cborplugin.Server) {
	e.write = s.Write
}

func (e *Courier) SetWriteFunc(writeFunc func(cborplugin.Command)) {
	e.write = writeFunc
}
