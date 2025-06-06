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
	Epoch           uint64
	EnvelopeReplies [2]*commands.ReplicaMessageReply
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

	if !reply.IsRead {
		e.log.Debug("CacheReply: not caching write reply")
		return
	}

	e.log.Debug("CacheReply: caching read reply")

	// Don't cache replies with nil envelope hash
	if reply.EnvelopeHash == nil {
		e.log.Debug("CacheReply: envelope hash is nil, not caching")
		return
	}

	e.dedupCacheLock.Lock()
	defer e.dedupCacheLock.Unlock()

	entry, ok := e.dedupCache[*reply.EnvelopeHash]
	if ok {
		e.log.Debugf("CacheReply: found existing cache entry for envelope hash %x", reply.EnvelopeHash)
		switch {
		case entry.EnvelopeReplies[0] == nil && entry.EnvelopeReplies[1] == nil:
			e.log.Debug("CacheReply: storing reply in slot 0")
			entry.EnvelopeReplies[0] = reply
		case entry.EnvelopeReplies[0] != nil && entry.EnvelopeReplies[1] == nil:
			e.log.Debug("CacheReply: storing reply in slot 1")
			entry.EnvelopeReplies[1] = reply
		case entry.EnvelopeReplies[0] != nil && entry.EnvelopeReplies[1] != nil:
			e.log.Debug("CacheReply: both slots already filled, not caching")
			// no-op. already cached both replies.
		}
	} else {
		e.log.Debugf("BUG: received an unknown EnvelopeHash %x from a replica reply", reply.EnvelopeHash)

		// Get current epoch, defaulting to 0 if PKI document is not available yet
		var currentEpoch uint64
		if pkiDoc := e.server.PKI.PKIDocument(); pkiDoc != nil {
			currentEpoch = pkiDoc.Epoch
		}

		e.log.Debug("CacheReply: creating new cache entry and storing reply in slot 0")
		e.dedupCache[*reply.EnvelopeHash] = &CourierBookKeeping{
			Epoch: currentEpoch,
			EnvelopeReplies: [2]*commands.ReplicaMessageReply{
				reply,
				nil,
			},
		}
	}

	// Log final cache state
	finalEntry := e.dedupCache[*reply.EnvelopeHash]
	reply0Available := finalEntry.EnvelopeReplies[0] != nil
	reply1Available := finalEntry.EnvelopeReplies[1] != nil
	e.log.Debugf("CacheReply: final cache state for %x - Reply[0]: %v, Reply[1]: %v", reply.EnvelopeHash, reply0Available, reply1Available)
}

func (e *Courier) handleNewMessage(isRead bool, envHash *[hash.HashSize]byte, courierMessage *common.CourierEnvelope) []byte {
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

	reply := &common.CourierEnvelopeReply{
		EnvelopeHash: envHash,
		ReplyIndex:   0,
		Payload:      nil,
		ErrorString:  "",
		ErrorCode:    0,
	}
	return reply.Bytes()
}

func (e *Courier) handleOldMessage(cacheEntry *CourierBookKeeping, envHash *[hash.HashSize]byte, courierMessage *common.CourierEnvelope) []byte {
	e.log.Debugf("handleOldMessage called for envelope hash: %x, requested ReplyIndex: %d", envHash, courierMessage.ReplyIndex)

	reply := &common.CourierEnvelopeReply{
		EnvelopeHash: envHash,
		ReplyIndex:   courierMessage.ReplyIndex,
		ErrorString:  "",
		ErrorCode:    0,
	}

	// Check if cacheEntry is nil before accessing its fields
	if cacheEntry == nil {
		e.log.Debugf("Cache entry is nil, no replies available")
		return reply.Bytes()
	}

	// Log cache state
	reply0Available := cacheEntry.EnvelopeReplies[0] != nil
	reply1Available := cacheEntry.EnvelopeReplies[1] != nil
	e.log.Debugf("Cache state - Reply[0]: %v, Reply[1]: %v", reply0Available, reply1Available)

	if cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex] != nil {
		e.log.Debugf("Found reply at requested index %d", courierMessage.ReplyIndex)
		reply.Payload = cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex].EnvelopeReply
	} else if cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex^1] != nil {
		e.log.Debugf("No reply at requested index %d, checking alternate index %d", courierMessage.ReplyIndex, courierMessage.ReplyIndex^1)
		reply.Payload = cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex^1].EnvelopeReply
		reply.ReplyIndex = courierMessage.ReplyIndex ^ 1
	} else {
		e.log.Debugf("No replies available in cache")
	}

	e.log.Debugf("handleOldMessage returning payload length: %d", len(reply.Payload))
	return reply.Bytes()
}

func (e *Courier) OnCommand(cmd cborplugin.Command) error {
	var request *cborplugin.Request
	switch r := cmd.(type) {
	case *cborplugin.Request:
		request = r
	default:
		return errors.New("Bug in courier-plugin: received invalid Command type")
	}

	courierMessage, err := common.CourierEnvelopeFromBytes(request.Payload)
	if err != nil {
		e.log.Debugf("Bug, failed to decode CBOR blob: %s", err)
		return err
	}
	envHash := courierMessage.EnvelopeHash()

	var replyPayload []byte
	e.dedupCacheLock.RLock()
	cacheEntry, ok := e.dedupCache[*envHash]
	e.dedupCacheLock.RUnlock()

	if ok {
		e.log.Debugf("OnCommand: Found cached entry for envelope hash %x, calling handleOldMessage", envHash)
		replyPayload = e.handleOldMessage(cacheEntry, envHash, courierMessage)
	} else {
		e.log.Debugf("OnCommand: No cached entry for envelope hash %x, calling handleNewMessage", envHash)
		e.dedupCacheLock.Lock()

		// Get current epoch, defaulting to 0 if PKI document is not available yet
		var currentEpoch uint64
		if pkiDoc := e.server.PKI.PKIDocument(); pkiDoc != nil {
			currentEpoch = pkiDoc.Epoch
		}

		e.dedupCache[*envHash] = &CourierBookKeeping{
			Epoch:           currentEpoch,
			EnvelopeReplies: [2]*commands.ReplicaMessageReply{nil, nil},
		}
		e.dedupCacheLock.Unlock()
		replyPayload = e.handleNewMessage(courierMessage.IsRead, envHash, courierMessage)
	}

	go func() {
		// send reply
		e.write(&cborplugin.Response{
			ID:      request.ID,
			SURB:    request.SURB,
			Payload: replyPayload,
		})
	}()
	return nil

}

func (e *Courier) RegisterConsumer(s *cborplugin.Server) {
	e.write = s.Write
}

func (e *Courier) SetWriteFunc(writeFunc func(cborplugin.Command)) {
	e.write = writeFunc
}
