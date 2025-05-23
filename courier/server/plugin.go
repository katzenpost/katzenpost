// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

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

	cmds           *commands.Commands
	geo            *geo.Geometry
	envelopeScheme nike.Scheme

	dedupCacheLock sync.RWMutex
	dedupCache     map[[hash.HashSize]byte]*CourierBookKeeping
}

// NewCourier returns a new Courier type.
// TODO: eventually we need to write the dedupCache to disk and so here's where
// we'd load it from disk.
func NewCourier(s *Server, cmds *commands.Commands, scheme nike.Scheme) *Courier {
	courier := &Courier{
		server:         s,
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
	s.courier = courier
	var server *cborplugin.Server

	server = cborplugin.NewServer(s.LogBackend().GetLogger("courier_plugin"), socketFile, new(cborplugin.RequestFactory), courier)
	fmt.Printf("%s\n", socketFile)
	server.Accept()
	server.Wait()
	err := os.Remove(socketFile)
	if err != nil {
		panic(err)
	}

}

func (e *Courier) CacheReply(reply *commands.ReplicaMessageReply) {
	e.dedupCacheLock.Lock()
	entry, ok := e.dedupCache[*reply.EnvelopeHash]
	if ok {
		switch {
		case entry.EnvelopeReplies[0] == nil && entry.EnvelopeReplies[1] == nil:
			entry.EnvelopeReplies[0] = reply
		case entry.EnvelopeReplies[0] != nil && entry.EnvelopeReplies[1] == nil:
			entry.EnvelopeReplies[1] = reply
		case entry.EnvelopeReplies[0] != nil && entry.EnvelopeReplies[1] != nil:
			// no-op. already cached both replies.
		}
	} else {
		e.dedupCache[*reply.EnvelopeHash] = &CourierBookKeeping{
			Epoch: e.server.pki.PKIDocument().Epoch,
			EnvelopeReplies: [2]*commands.ReplicaMessageReply{
				reply,
				nil,
			},
		}
	}
	e.dedupCacheLock.Unlock()
}

func (e *Courier) handleNewMessage(isRead bool, envHash *[hash.HashSize]byte, courierMessage *common.CourierEnvelope) []byte {
	replicas := make([]*commands.ReplicaMessage, 2)

	// replica 1
	e.server.log.Debug("---------- OnCommand: proxying to replica1")
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

	// replica 2
	e.server.log.Debug("---------- OnCommand: proxying to replica2")
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
	reply := &common.CourierEnvelopeReply{
		EnvelopeHash: envHash,
		ReplyIndex:   courierMessage.ReplyIndex,
		ErrorString:  "",
		ErrorCode:    0,
	}

	if cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex] != nil {
		reply.Payload = cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex].EnvelopeReply
	} else {
		if cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex^1] != nil {
			reply.Payload = cacheEntry.EnvelopeReplies[courierMessage.ReplyIndex^1].EnvelopeReply
			reply.ReplyIndex = courierMessage.ReplyIndex ^ 1
		}
	}

	return reply.Bytes()
}

func (e *Courier) OnCommand(cmd cborplugin.Command) error {

	// NOTE(David): storage replica read replies needs to go into the dedup cache

	e.server.log.Debug("---------- OnCommand BEGIN")
	var request *cborplugin.Request
	switch r := cmd.(type) {
	case *cborplugin.Request:
		request = r
	default:
		return errors.New("---------- courier-plugin: Invalid Command type")
	}

	courierMessage, err := common.CourierEnvelopeFromBytes(request.Payload)
	if err != nil {
		e.server.log.Debugf("---------- CBOR DECODE FAIL: %s", err)
		return err
	}
	envHash := courierMessage.EnvelopeHash()

	var replyPayload []byte
	e.dedupCacheLock.RLock()
	cacheEntry, ok := e.dedupCache[*envHash]
	e.dedupCacheLock.RUnlock()
	if ok {
		replyPayload = e.handleOldMessage(cacheEntry, envHash, courierMessage)
	} else {
		e.dedupCacheLock.Lock()
		e.dedupCache[*envHash] = &CourierBookKeeping{
			Epoch:           e.server.pki.PKIDocument().Epoch,
			EnvelopeReplies: [2]*commands.ReplicaMessageReply{nil, nil},
		}
		e.dedupCacheLock.Unlock()
		replyPayload = e.handleNewMessage(courierMessage.IsRead, envHash, courierMessage)
	}

	e.server.log.Debug("---------- OnCommand END... sending reply")

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
