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

	"gopkg.in/op/go-logging.v1"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/client2/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	pigeonholeCommon "github.com/katzenpost/katzenpost/pigeonhole/common"
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

	copyCacheLock sync.RWMutex
	copyCache     map[[hash.HashSize]byte]chan *commands.ReplicaMessageReply
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
		copyCache:      make(map[[hash.HashSize]byte]chan *commands.ReplicaMessageReply),
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

func (e *Courier) handleCourierEnvelope(courierMessage *common.CourierEnvelope) {
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
}

func (e *Courier) handleNewMessage(envHash *[hash.HashSize]byte, courierMessage *common.CourierEnvelope) *common.CourierQueryReply {
	e.handleCourierEnvelope(courierMessage)
	reply := &common.CourierQueryReply{
		CourierEnvelopeReply: &common.CourierEnvelopeReply{
			EnvelopeHash: envHash,
			ReplyIndex:   0,
			Payload:      nil,
			ErrorCode:    0,
		},
		CopyCommandReply: nil,
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
		reply := e.cacheHandleCourierEnvelope(courierQuery.CourierEnvelope)

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

func (e *Courier) cacheHandleCourierEnvelope(courierMessage *common.CourierEnvelope) *common.CourierQueryReply {
	envHash := courierMessage.EnvelopeHash()

	e.dedupCacheLock.RLock()
	cacheEntry, ok := e.dedupCache[*envHash]
	e.dedupCacheLock.RUnlock()

	if ok {
		e.log.Debugf("OnCommand: Found cached entry for envelope hash %x, calling handleOldMessage", envHash)
		return e.handleOldMessage(cacheEntry, envHash, courierMessage)
	}

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
	return e.handleNewMessage(envHash, courierMessage)
}

func (e *Courier) handleCopyCommand(copyCmd *common.CopyCommand) *common.CourierQueryReply {
	// here we copy BACAP Boxes from the readcap which we can derive from the given writecap.
	// we don't know exactly how many Boxes but if we encounter a final Box it will have
	// content which are padded with zeros instead of the next CBOR blob.

	readcap := copyCmd.WriteCap.UniversalReadCap()
	statefulReader, err := bacap.NewStatefulReader(readcap, constants.PIGEONHOLE_CTX)
	if err != nil {
		e.log.Debugf("Failed to create stateful reader from readcap: %s", err)
		return &common.CourierQueryReply{
			CourierEnvelopeReply: nil,
			CopyCommandReply: &common.CopyCommandReply{
				ErrorCode: 2, // readcap derivation error
			},
		}
	}

	// read all boxes in the copy sequence
	boxIDList := make([]*[bacap.BoxIDSize]byte, 0)
	var boxPlaintext []byte
	isLast := false
	buffer := bytes.NewBuffer(nil)
	for isLast == false {
		boxID, err := statefulReader.NextBoxID()
		if err != nil {
			e.log.Debugf("Failed to get next BoxID: %s", err)
			return &common.CourierQueryReply{
				CourierEnvelopeReply: nil,
				CopyCommandReply: &common.CopyCommandReply{
					ErrorCode: 3, // read error
				},
			}
		}
		boxIDList = append(boxIDList, boxID)
		boxPlaintext, isLast, err = e.readNextBox(statefulReader)
		if err != nil {
			e.log.Debugf("Failed to read next Box: %s", err)
			return &common.CourierQueryReply{
				CourierEnvelopeReply: nil,
				CopyCommandReply: &common.CopyCommandReply{
					ErrorCode: 3, // read error
				},
			}
		}
		buffer.Write(boxPlaintext)
	}

	// make a CBOR decoder to decode buffer
	decMode, err := cbor.DecOptions{}.DecMode()
	if err != nil {
		e.log.Debugf("Failed to create CBOR decoder: %s", err)
		return &common.CourierQueryReply{
			CourierEnvelopeReply: nil,
			CopyCommandReply: &common.CopyCommandReply{
				ErrorCode: 3, // read error
			},
		}
	}
	decoder := decMode.NewDecoder(buffer)

	// decode all of buffer into CourierEnvelopes
	envelopes := make([]*common.CourierEnvelope, 0)
	for buffer.Len() > 0 {
		var v interface{}
		err := decoder.Decode(&v)
		if err != nil {
			e.log.Debugf("Failed to decode CBOR: %s", err)
			return &common.CourierQueryReply{
				CourierEnvelopeReply: nil,
				CopyCommandReply: &common.CopyCommandReply{
					ErrorCode: 3, // read error
				},
			}
		}
		envelope, ok := v.(*common.CourierEnvelope)
		if !ok {
			e.log.Debugf("BUG: Type assertion failed, expected *common.CourierEnvelope, got %T", v)
			return &common.CourierQueryReply{
				CourierEnvelopeReply: nil,
				CopyCommandReply: &common.CopyCommandReply{
					ErrorCode: 3, // read error
				},
			}
		}
		envelopes = append(envelopes, envelope)
	}

	// Send each CourierEnvelope to the replicas.
	for _, envelope := range envelopes {
		e.handleCourierEnvelope(envelope)
	}

	// XXX TODO FIXME: write tombstones to all the Boxes in boxIDList.

	reply := &common.CourierQueryReply{
		CourierEnvelopeReply: nil,
		CopyCommandReply: &common.CopyCommandReply{
			ErrorCode: 0, // success
		},
	}

	return reply
}

func (e *Courier) readNextBox(statefulReader *bacap.StatefulReader) (boxPlaintext []byte, isLast bool, err error) {
	boxID, err := statefulReader.NextBoxID()
	if err != nil {
		e.log.Debugf("Failed to get next BoxID: %s", err)
		return nil, false, errors.New("failed to get next BoxID")
	}
	replicaReadReply, err := e.readBoxFromReplica(boxID)
	if err != nil {
		e.log.Debugf("Failed to read Box from replica: %s", err)
		return nil, false, errors.New("failed to read Box from replica")
	}
	return replicaReadReply.Payload, replicaReadReply.IsLast, nil
}

// here we send a read request to the replica and get a reply
func (e *Courier) readBoxFromReplica(boxID *[bacap.BoxIDSize]byte) (*common.ReplicaReadReply, error) {
	doc := e.server.PKI.PKIDocument()
	_, replicaPubKeys, err := pigeonholeCommon.GetRandomIntermediateReplicas(doc)
	if err != nil {
		return nil, err
	}

	readMsg := common.ReplicaRead{
		BoxID: boxID,
	}
	msg := &common.ReplicaInnerMessage{
		ReplicaRead: &readMsg,
	}

	mkemPrivateKey, mkemCiphertext := common.MKEMNikeScheme.Encapsulate(replicaPubKeys, msg.Bytes())
	mkemPublicKey := mkemPrivateKey.Public()
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

	e.server.SendMessage(0, query)

	reply := <-e.copyCache[*envHash]
	delete(e.copyCache, *envHash)

	if reply.ErrorCode != 0 {
		return nil, errors.New("failed to read Box from replica")
	}

	rawPlaintext, err := common.MKEMNikeScheme.DecryptEnvelope(mkemPrivateKey, replicaPubKeys[0], reply.EnvelopeReply)
	if err != nil {
		return nil, err
	}

	innerMsg, err := common.ReplicaMessageReplyInnerMessageFromBytes(rawPlaintext)
	if err != nil {
		return nil, err
	}

	if innerMsg.ReplicaReadReply == nil {
		return nil, errors.New("failed to read Box from replica")
	}

	return innerMsg.ReplicaReadReply, nil
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
