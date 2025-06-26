// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/nike"
	hpqcRand "github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client2/common"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/constants"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/pigeonhole"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

const (
	// AppIDLength is the length of the application ID in bytes.
	AppIDLength = 16
)

type gcReply struct {
	id    *[MessageIDLength]byte
	appID *[AppIDLength]byte
}

type sphinxReply struct {
	surbID     *[sphinxConstants.SURBIDLength]byte
	ciphertext []byte
}

type replyDescriptor struct {
	ID      *[MessageIDLength]byte
	appID   *[AppIDLength]byte
	surbKey []byte
}

type Daemon struct {
	worker.Worker

	logbackend *log.Backend
	log        *logging.Logger

	cfg      *config.Config
	client   *Client
	listener *listener
	egressCh chan *Request

	replies   map[[sphinxConstants.SURBIDLength]byte]replyDescriptor
	decoys    map[[sphinxConstants.SURBIDLength]byte]replyDescriptor
	replyLock *sync.Mutex

	timerQueue *TimerQueue
	ingressCh  chan *sphinxReply
	gcSurbIDCh chan *[sphinxConstants.SURBIDLength]byte

	gcTimerQueue *TimerQueue
	gcReplyCh    chan *gcReply

	arqTimerQueue *TimerQueue
	arqSurbIDMap  map[[sphinxConstants.SURBIDLength]byte]*ARQMessage
	arqResendCh   chan *[sphinxConstants.SURBIDLength]byte

	channelReplies         map[[sphinxConstants.SURBIDLength]byte]replyDescriptor
	channelRepliesLock     *sync.RWMutex
	surbIDToChannelMap     map[[sphinxConstants.SURBIDLength]byte][thin.ChannelIDLength]byte
	surbIDToChannelMapLock *sync.RWMutex
	channelMap             map[[thin.ChannelIDLength]byte]*ChannelDescriptor
	channelMapLock         *sync.RWMutex

	// New API fields (separate from old API)
	newSurbIDToChannelMap     map[[sphinxConstants.SURBIDLength]byte]uint16
	newSurbIDToChannelMapLock *sync.RWMutex
	newChannelMap             map[uint16]*ChannelDescriptor
	newChannelMapLock         *sync.RWMutex

	// Capability deduplication maps to prevent reusing read/write capabilities
	usedReadCaps   map[[hash.HashSize]byte]bool // Maps hash of ReadCap to true
	usedWriteCaps  map[[hash.HashSize]byte]bool // Maps hash of WriteCap to true
	capabilityLock *sync.RWMutex                // Protects both capability maps

	// Cryptographically secure random number generator
	secureRand *mrand.Rand

	haltOnce sync.Once
}

func NewDaemon(cfg *config.Config) (*Daemon, error) {
	egressSize := 2
	ingressSize := 200
	d := &Daemon{
		cfg:          cfg,
		egressCh:     make(chan *Request, egressSize),
		ingressCh:    make(chan *sphinxReply, ingressSize),
		replies:      make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		decoys:       make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		gcSurbIDCh:   make(chan *[sphinxConstants.SURBIDLength]byte),
		gcReplyCh:    make(chan *gcReply),
		replyLock:    new(sync.Mutex),
		arqSurbIDMap: make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		arqResendCh:  make(chan *[sphinxConstants.SURBIDLength]byte, 2),
		// pigeonhole channel fields:
		channelReplies:         make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		channelRepliesLock:     new(sync.RWMutex),
		surbIDToChannelMap:     make(map[[sphinxConstants.SURBIDLength]byte][thin.ChannelIDLength]byte),
		surbIDToChannelMapLock: new(sync.RWMutex),
		channelMap:             make(map[[thin.ChannelIDLength]byte]*ChannelDescriptor),
		channelMapLock:         new(sync.RWMutex),
		// New API fields
		newSurbIDToChannelMap:     make(map[[sphinxConstants.SURBIDLength]byte]uint16),
		newSurbIDToChannelMapLock: new(sync.RWMutex),
		newChannelMap:             make(map[uint16]*ChannelDescriptor),
		newChannelMapLock:         new(sync.RWMutex),
		// capability deduplication fields:
		usedReadCaps:   make(map[[hash.HashSize]byte]bool),
		usedWriteCaps:  make(map[[hash.HashSize]byte]bool),
		capabilityLock: new(sync.RWMutex),
		// Initialize cryptographically secure random number generator
		secureRand: hpqcRand.NewMath(),
	}
	err := d.initLogging()
	if err != nil {
		return nil, err
	}
	return d, nil
}

// generateUniqueChannelID generates a unique uint16 channel ID that's not already in use
func (d *Daemon) generateUniqueChannelID() uint16 {
	d.newChannelMapLock.Lock()
	defer d.newChannelMapLock.Unlock()

	for {
		// Generate a random uint16
		var channelID uint16
		binary.Read(rand.Reader, binary.BigEndian, &channelID)

		// Check if it's already in use
		if _, exists := d.newChannelMap[channelID]; !exists {
			// Reserve the ID by adding an empty entry (will be replaced with actual descriptor)
			d.newChannelMap[channelID] = nil
			return channelID
		}
	}
}

func (d *Daemon) initLogging() error {
	f := d.cfg.Logging.File
	if !d.cfg.Logging.Disable && d.cfg.Logging.File != "" {
		if !filepath.IsAbs(f) {
			return errors.New("log file path must be absolute path")
		}
	}

	var err error
	d.logbackend, err = log.New(f, d.cfg.Logging.Level, d.cfg.Logging.Disable)
	if err == nil {
		d.log = d.logbackend.GetLogger("katzenpost/client2")
	}
	return err
}

// generateUniqueNewChannelID generates a unique uint16 channel ID for the new API
func (d *Daemon) generateUniqueNewChannelID() uint16 {
	d.newChannelMapLock.Lock()
	defer d.newChannelMapLock.Unlock()

	for {
		// Generate a random uint16
		var channelID uint16
		binary.Read(rand.Reader, binary.BigEndian, &channelID)

		// Check if it's already in use
		if _, exists := d.newChannelMap[channelID]; !exists {
			// Reserve the ID by adding an empty entry (will be replaced with actual descriptor)
			d.newChannelMap[channelID] = nil
			return channelID
		}
	}
}

// Shutdown cleanly shuts down a given Server instance.
func (d *Daemon) Shutdown() {
	d.haltOnce.Do(func() { d.halt() })
}

func (d *Daemon) halt() {
	d.log.Debug("Stopping thin client listener")
	d.listener.Shutdown()

	d.log.Debug("Stopping workers first to prevent channel deadlocks")
	d.Halt() // shutdown ingressWorker and egressWorker first

	d.log.Debug("Stopping timerQueue")
	d.timerQueue.Halt()
	d.log.Debug("Stopping gcTimerQueue")
	d.gcTimerQueue.Halt()
	d.log.Debug("Stopping arqTimerQueue")
	d.arqTimerQueue.Halt()

	d.log.Debug("Stopping client")
	d.client.Shutdown()
}

func (d *Daemon) Start() error {
	d.log.Debug("Start daemon")
	var err error
	rates := &Rates{}
	if d.cfg.CachedDocument != nil {
		rates = ratesFromPKIDoc(d.cfg.CachedDocument)
	}

	d.client, err = New(d.cfg, d.logbackend)
	if err != nil {
		return err
	}

	d.listener, err = NewListener(d.client, rates, d.egressCh, d.logbackend)
	if err != nil {
		return err
	}

	d.cfg.Callbacks = &config.Callbacks{}
	d.cfg.Callbacks.OnACKFn = d.proxyReplies
	d.cfg.Callbacks.OnConnFn = d.listener.updateConnectionStatus
	d.cfg.Callbacks.OnDocumentFn = d.onDocument

	d.timerQueue = NewTimerQueue(func(rawSurbID interface{}) {
		surbID, ok := rawSurbID.(*[sphinxConstants.SURBIDLength]byte)
		if !ok {
			panic("wtf, failed type assertion!")
		}
		select {
		case d.gcSurbIDCh <- surbID:
		case <-d.HaltCh():
			return
		case <-time.After(5 * time.Second):
			d.log.Debugf("Timeout sending to gcSurbIDCh for SURB ID %x", surbID[:])
			return
		}
	})
	d.timerQueue.Start()
	d.arqTimerQueue = NewTimerQueue(func(rawSurbID interface{}) {
		d.log.Info("ARQ TimerQueue callback!")
		surbID, ok := rawSurbID.(*[sphinxConstants.SURBIDLength]byte)
		if !ok {
			panic("wtf, failed type assertion!")
		}
		d.log.Warning("BEFORE ARQ resend")
		// Use a timeout to prevent blocking during shutdown
		go func() {
			select {
			case <-d.HaltCh():
				return
			case <-time.After(10 * time.Second):
				d.log.Debugf("ARQ resend timeout for SURB ID %x", surbID[:])
				return
			default:
				d.arqResend(surbID)
			}
		}()
		d.log.Warning("AFTER ARQ resend")
	})
	d.arqTimerQueue.Start()
	d.gcTimerQueue = NewTimerQueue(func(rawGCReply interface{}) {
		myGcReply, ok := rawGCReply.(*gcReply)
		if !ok {
			panic("wtf, failed type assertion!")
		}
		select {
		case d.gcReplyCh <- myGcReply:
		case <-d.HaltCh():
			return
		case <-time.After(5 * time.Second):
			d.log.Debugf("Timeout sending to gcReplyCh for message ID %x", myGcReply.id[:])
			return
		}
	})
	d.gcTimerQueue.Start()

	d.Go(d.ingressWorker)
	d.Go(d.egressWorker)

	return d.client.Start()
}

func (d *Daemon) onDocument(doc *cpki.Document) {
	slopFactor := 0.8
	pollProvider := time.Duration((1.0 / (doc.LambdaP + doc.LambdaL)) * slopFactor * float64(time.Millisecond))
	d.client.SetPollInterval(pollProvider)
	d.listener.updateFromPKIDoc(doc)
}

func (d *Daemon) proxyReplies(surbID *[sphinxConstants.SURBIDLength]byte, ciphertext []byte) error {
	select {
	case d.ingressCh <- &sphinxReply{
		surbID:     surbID,
		ciphertext: ciphertext}:
	case <-d.HaltCh():
		return nil
	}
	return nil
}

func (d *Daemon) egressWorker() {
	for {
		select {
		case <-d.HaltCh():
			d.log.Debug("egressWorker shutting down")
			return
		case surbID := <-d.arqResendCh:
			d.arqDoResend(surbID)
		case request := <-d.egressCh:
			switch {
			case request.SendLoopDecoy != nil:
				d.sendLoopDecoy(request)
			case request.SendDropDecoy != nil:
				d.sendDropDecoy()
			case request.SendMessage != nil:
				d.send(request)
			case request.SendARQMessage != nil:
				d.send(request)

				// New Pigeonhole Channel related commands proceed here:

			case request.CreateWriteChannel != nil:
				d.createWriteChannel(request)
			case request.CreateReadChannelV2 != nil:
				d.createReadChannelV2(request)
			case request.WriteChannelV2 != nil:
				d.writeChannelV2(request)
			case request.ReadChannelV2 != nil:
				d.readChannelV2(request)

				// Old Pigeonhole Channel related commands proceed here:

			case request.CreateChannel != nil:
				d.createChannel(request)
			case request.CreateReadChannel != nil:
				d.createReadChannel(request)
			case request.WriteChannel != nil:
				d.writeChannel(request)
			case request.ReadChannel != nil:
				d.readChannel(request)
			case request.CopyChannel != nil:
				d.copyChannel(request)
			default:
				panic("send operation not fully specified")
			}
		}
	}
}

func (d *Daemon) ingressWorker() {
	for {
		select {
		case <-d.HaltCh():
			return
		case mygcreply := <-d.gcReplyCh:
			response := &Response{
				AppID: mygcreply.appID,
				MessageIDGarbageCollected: &thin.MessageIDGarbageCollected{
					MessageID: mygcreply.id,
				},
			}
			conn := d.listener.getConnection(mygcreply.appID)
			if conn == nil {
				d.log.Errorf("no connection associated with AppID %x", mygcreply.appID[:])
				continue
			}
			err := conn.sendResponse(response)
			if err != nil {
				d.log.Errorf("failed to send Response: %s", err)
			}
		case surbID := <-d.gcSurbIDCh:
			d.channelRepliesLock.RLock()
			_, ok := d.channelReplies[*surbID]
			d.channelRepliesLock.RUnlock()

			if ok {
				d.log.Debugf("Timer expired for channel SURB ID %x, but keeping state for retries", surbID[:])
				continue
			}

			d.replyLock.Lock()
			delete(d.replies, *surbID)
			delete(d.decoys, *surbID)
			d.replyLock.Unlock()
		case reply := <-d.ingressCh:
			d.handleReply(reply)
		}
	}
}

func (d *Daemon) handleReply(reply *sphinxReply) {
	isChannelReply := false
	isReply := false
	isARQReply := false
	isDecoy := false
	desc := replyDescriptor{}
	arqMessage := &ARQMessage{}

	d.replyLock.Lock()
	myReplyDescriptor, isReply := d.replies[*reply.surbID]
	myDecoyDescriptor, isDecoy := d.decoys[*reply.surbID]
	arqMessage, isARQReply = d.arqSurbIDMap[*reply.surbID]
	d.replyLock.Unlock()

	d.channelRepliesLock.RLock()
	myChannelReplyDescriptor, isChannelReply := d.channelReplies[*reply.surbID]
	d.channelRepliesLock.RUnlock()

	switch {
	case isReply:
		desc = myReplyDescriptor
		d.replyLock.Lock()
		delete(d.replies, *reply.surbID)
		d.replyLock.Unlock()
	case isDecoy:
		desc = myDecoyDescriptor
		d.replyLock.Lock()
		delete(d.decoys, *reply.surbID)
		d.replyLock.Unlock()
	case isARQReply:
		desc = replyDescriptor{
			ID:      arqMessage.MessageID,
			appID:   arqMessage.AppID,
			surbKey: arqMessage.SURBDecryptionKeys,
		}
		peeked := d.arqTimerQueue.Peek()
		if peeked != nil {
			peekSurbId := peeked.Value.(*[sphinxConstants.SURBIDLength]byte)
			if hmac.Equal(arqMessage.SURBID[:], peekSurbId[:]) {
				d.arqTimerQueue.Pop()
			}
		}
		d.replyLock.Lock()
		delete(d.arqSurbIDMap, *reply.surbID)
		d.replyLock.Unlock()
	case isChannelReply:
		d.log.Debugf("Received channel reply for SURB ID %x", reply.surbID[:])
		desc = myChannelReplyDescriptor
	default:
		return
	}

	plaintext, err := d.client.sphinx.DecryptSURBPayload(reply.ciphertext, desc.surbKey)
	if err != nil {
		d.log.Infof("SURB reply decryption error: %s", err.Error())
		return
	}

	// XXX FIXME consume statistics on our loop decoys for n-1 detection
	if isDecoy {
		return
	}

	conn := d.listener.getConnection(desc.appID)
	if conn == nil {
		d.log.Errorf("no connection associated with AppID %x", desc.appID[:])
		return
	}
	if isChannelReply {
		err := d.handleChannelReply(desc.appID, desc.ID, reply.surbID, plaintext, conn)
		if err == nil {
			d.log.Infof("Handled channel reply book keeping for SURB ID %x, sent response to client", reply.surbID[:])
			d.channelRepliesLock.Lock()
			delete(d.channelReplies, *reply.surbID)
			d.channelRepliesLock.Unlock()

			// Clean up from both old and new API maps
			d.surbIDToChannelMapLock.Lock()
			delete(d.surbIDToChannelMap, *reply.surbID)
			d.surbIDToChannelMapLock.Unlock()

			d.newSurbIDToChannelMapLock.Lock()
			delete(d.newSurbIDToChannelMap, *reply.surbID)
			d.newSurbIDToChannelMapLock.Unlock()
		}
	} else {
		conn.sendResponse(&Response{
			AppID: desc.appID,
			MessageReplyEvent: &thin.MessageReplyEvent{
				MessageID: desc.ID,
				SURBID:    reply.surbID,
				Payload:   plaintext,
			},
		})
	}
}

// handleChannelReply tries to handle the reply and if successful it sends a
// response to the appropriate thin client connection. Otherwise it returns an error.
func (d *Daemon) handleChannelReply(appid *[AppIDLength]byte,
	mesgID *[MessageIDLength]byte,
	surbid *[sphinxConstants.SURBIDLength]byte,
	plaintext []byte,
	conn *incomingConn) error {

	d.log.Infof("CHANNEL REPLY: Looking up SURB ID %x, payload size: %d bytes", surbid[:8], len(plaintext))

	// Try new API first, then fall back to old API
	newChannelID, newChannelDesc, newErr := d.lookupNewChannel(surbid)
	if newErr == nil {
		d.log.Infof("NEW API: Found channel %d for SURB ID %x, payload size: %d bytes", newChannelID, surbid[:8], len(plaintext))
		// New API channel found
		return d.handleNewChannelReply(appid, mesgID, surbid, plaintext, conn, newChannelID, newChannelDesc)
	}

	// Fall back to old API
	oldChannelID, oldChannelDesc, oldErr := d.lookupChannel(surbid)
	if oldErr != nil {
		d.log.Errorf("SURB ID %x not found in either old or new API maps", surbid[:8])
		return fmt.Errorf("SURB ID not found in either API: new=%v, old=%v", newErr, oldErr)
	}

	d.log.Infof("OLD API: Found channel %x for SURB ID %x", oldChannelID[:8], surbid[:8])
	// Old API channel found
	return d.handleOldChannelReply(appid, mesgID, surbid, plaintext, conn, oldChannelID, oldChannelDesc)
}

// handleNewChannelReply handles channel replies for the new API
func (d *Daemon) handleNewChannelReply(appid *[AppIDLength]byte,
	mesgID *[MessageIDLength]byte,
	surbid *[sphinxConstants.SURBIDLength]byte,
	plaintext []byte,
	conn *incomingConn,
	channelID uint16,
	channelDesc *ChannelDescriptor) error {

	d.log.Infof("NEW API REPLY: Processing reply for channel %d, payload size: %d bytes", channelID, len(plaintext))

	if len(plaintext) == 0 {
		d.log.Infof("NEW API REPLY: Empty payload for channel %d, not sending response", channelID)
		return nil
	}

	isReader, isWriter, err := d.validateNewChannel(channelID, channelDesc)
	if err != nil {
		return err
	}

	// First, parse the courier query reply to check what type of reply it is
	d.log.Infof("NEW API REPLY: Parsing courier query reply...")
	courierQueryReply, err := pigeonhole.ParseCourierQueryReply(plaintext)
	if err != nil {
		d.log.Errorf("NEW API REPLY: Failed to unmarshal courier query reply: %s", err)
		return fmt.Errorf("failed to unmarshal courier query reply: %s", err)
	}

	// Handle copy command replies
	if courierQueryReply.CopyCommandReply != nil {
		d.log.Infof("NEW API REPLY: Handling copy command reply")
		return d.handleNewCopyReply(appid, channelID, courierQueryReply.CopyCommandReply, conn)
	}

	// Handle envelope replies (read/write operations)
	if courierQueryReply.EnvelopeReply != nil {
		d.log.Infof("NEW API REPLY: Handling envelope reply")

		// Check if the envelope reply has an empty payload (no data available yet)
		if len(courierQueryReply.EnvelopeReply.Payload) == 0 {
			d.log.Infof("NEW API REPLY: Empty payload - no data available yet, sending empty response")
			// Send empty response to client so they can retry
			err := conn.sendResponse(&Response{
				AppID: appid,
				MessageReplyEvent: &thin.MessageReplyEvent{
					MessageID: mesgID,
					Payload:   nil, // Empty payload
					Err:       nil, // No error - just no data yet
				},
			})
			if err != nil {
				d.log.Errorf("NEW API REPLY: Failed to send empty response: %s", err)
				return err
			}
			return nil
		}

		env, envelopeDesc, privateKey, err := d.processEnvelopeReply(courierQueryReply.EnvelopeReply, channelDesc)
		if err != nil {
			d.log.Errorf("NEW API REPLY: Failed to process envelope reply: %s", err)
			return err
		}

		d.log.Infof("NEW API REPLY: Decrypting MKEM envelope...")
		innerMsg, err := d.decryptMKEMEnvelope(env, envelopeDesc, privateKey)
		if err != nil {
			d.log.Errorf("NEW API REPLY: Failed to decrypt MKEM envelope: %s", err)
			return err
		}

		envHash := (*[hash.HashSize]byte)(env.EnvelopeHash[:])

		switch {
		case innerMsg.ReadReply != nil:
			params := &NewReplyHandlerParams{
				AppID:       appid,
				MessageID:   mesgID,
				ChannelID:   channelID,
				ChannelDesc: channelDesc,
				EnvHash:     envHash,
				IsReader:    isReader,
				IsWriter:    isWriter,
				Conn:        conn,
			}
			return d.handleNewReadReply(params, innerMsg.ReadReply)
		case innerMsg.WriteReply != nil:
			params := &NewReplyHandlerParams{
				AppID:       appid,
				MessageID:   mesgID,
				ChannelID:   channelID,
				ChannelDesc: channelDesc,
				EnvHash:     envHash,
				IsReader:    isReader,
				IsWriter:    isWriter,
				Conn:        conn,
			}
			return d.handleNewWriteReply(params, innerMsg.WriteReply)
		}
		d.log.Errorf("bug 6, invalid book keeping for channelID %d", channelID)
		return fmt.Errorf("bug 6, invalid book keeping for channelID %d", channelID)
	}

	d.log.Errorf("courier query reply contains neither envelope reply nor copy command reply")
	return fmt.Errorf("courier query reply contains neither envelope reply nor copy command reply")
}

// lookupChannel finds the channel descriptor for a given SURB ID (old API)
func (d *Daemon) lookupChannel(surbid *[sphinxConstants.SURBIDLength]byte) ([thin.ChannelIDLength]byte, *ChannelDescriptor, error) {
	d.surbIDToChannelMapLock.RLock()
	channelID, ok := d.surbIDToChannelMap[*surbid]
	d.surbIDToChannelMapLock.RUnlock()
	if !ok {
		d.log.Errorf("no channelID found for surbID %x", surbid[:])
		return [thin.ChannelIDLength]byte{}, nil, fmt.Errorf("no channelID found for surbID %x", surbid[:])
	}

	d.channelMapLock.RLock()
	channelDesc, ok := d.channelMap[channelID]
	d.channelMapLock.RUnlock()
	if !ok {
		d.log.Errorf("no channel found for channelID %x", channelID[:])
		return [thin.ChannelIDLength]byte{}, nil, fmt.Errorf("no channel found for channelID %x", channelID[:])
	}

	return channelID, channelDesc, nil
}

// lookupNewChannel finds the channel descriptor for a given SURB ID (new API)
func (d *Daemon) lookupNewChannel(surbid *[sphinxConstants.SURBIDLength]byte) (uint16, *ChannelDescriptor, error) {
	d.newSurbIDToChannelMapLock.RLock()
	channelID, ok := d.newSurbIDToChannelMap[*surbid]
	d.newSurbIDToChannelMapLock.RUnlock()
	if !ok {
		d.log.Errorf("no channelID found for surbID %x in new API", surbid[:])
		return 0, nil, fmt.Errorf("no channelID found for surbID %x in new API", surbid[:])
	}

	d.newChannelMapLock.RLock()
	channelDesc, ok := d.newChannelMap[channelID]
	d.newChannelMapLock.RUnlock()
	if !ok {
		d.log.Errorf("no channel found for channelID %d in new API", channelID)
		return 0, nil, fmt.Errorf("no channel found for channelID %d in new API", channelID)
	}

	return channelID, channelDesc, nil
}

// validateChannel performs sanity checks on the channel descriptor and determines channel type
func (d *Daemon) validateChannel(channelID [thin.ChannelIDLength]byte, channelDesc *ChannelDescriptor) (bool, bool, error) {
	// sanity check
	if channelDesc.StatefulReader == nil && channelDesc.StatefulWriter == nil {
		d.log.Errorf("bug 1, invalid book keeping for channelID %x", channelID[:])
		return false, false, fmt.Errorf("bug 1, invalid book keeping for channelID %x", channelID[:])
	}
	if channelDesc.StatefulReader != nil && channelDesc.StatefulWriter != nil {
		d.log.Errorf("bug 2, invalid book keeping for channelID %x", channelID[:])
		return false, false, fmt.Errorf("bug 2, invalid book keeping for channelID %x", channelID[:])
	}
	if channelDesc.EnvelopeDescriptors == nil {
		d.log.Errorf("bug 3, invalid book keeping for channelID %x", channelID[:])
		return false, false, fmt.Errorf("bug 3, invalid book keeping for channelID %x", channelID[:])
	}

	isReader := channelDesc.StatefulReader != nil
	isWriter := channelDesc.StatefulWriter != nil
	return isReader, isWriter, nil
}

// processEnvelopeReply processes the courier envelope reply and extracts necessary information
func (d *Daemon) processEnvelopeReply(env *pigeonhole.CourierEnvelopeReply, channelDesc *ChannelDescriptor) (*pigeonhole.CourierEnvelopeReply, *EnvelopeDescriptor, nike.PrivateKey, error) {
	envHash := (*[hash.HashSize]byte)(env.EnvelopeHash[:])

	// DEBUG: Log envelope hash and map size when processing reply
	channelDesc.EnvelopeDescriptorsLock.RLock()
	mapSize := len(channelDesc.EnvelopeDescriptors)
	envelopeDesc, ok := channelDesc.EnvelopeDescriptors[*envHash]
	channelDesc.EnvelopeDescriptorsLock.RUnlock()

	fmt.Printf("PROCESSING REPLY ENVELOPE HASH: %x (map size: %d, exists: %t)\n", envHash[:], mapSize, ok)

	if !ok {
		d.log.Errorf("no envelope descriptor found for hash %x", envHash[:])
		return nil, nil, nil, fmt.Errorf("no envelope descriptor found for hash %x", envHash[:])
	}

	privateKey, err := replicaCommon.NikeScheme.UnmarshalBinaryPrivateKey(envelopeDesc.EnvelopeKey)
	if err != nil {
		d.log.Errorf("failed to unmarshal private key: %s", err)
		return nil, nil, nil, fmt.Errorf("failed to unmarshal private key: %s", err)
	}

	if len(env.Payload) == 0 {
		d.log.Debugf("received empty payload for envelope hash %x - no data available yet", envHash[:])
		return nil, nil, nil, fmt.Errorf("no data available for read operation")
	}

	return env, envelopeDesc, privateKey, nil
}

// decryptMKEMEnvelope decrypts the MKEM envelope and returns the inner message
func (d *Daemon) decryptMKEMEnvelope(env *pigeonhole.CourierEnvelopeReply, envelopeDesc *EnvelopeDescriptor, privateKey nike.PrivateKey) (*pigeonhole.ReplicaMessageReplyInnerMessage, error) {
	mkemPrivateKeyBytes, _ := privateKey.MarshalBinary()
	fmt.Printf("BOB DECRYPTS WITH MKEM KEY: %x\n", mkemPrivateKeyBytes[:16]) // First 16 bytes for brevity

	d.log.Debugf("MKEM DECRYPT: Starting decryption with payload size %d bytes", len(env.Payload))

	_, doc := d.client.CurrentDocument()
	if doc == nil {
		d.log.Errorf("no pki doc found")
		return nil, fmt.Errorf("no pki doc found")
	}

	replicaEpoch := replicaCommon.ConvertNormalToReplicaEpoch(envelopeDesc.Epoch)

	// Try both replicas from the original envelope
	var rawInnerMsg []byte
	for _, replicaNum := range envelopeDesc.ReplicaNums {
		desc, err := replicaCommon.ReplicaNum(replicaNum, doc)
		if err != nil {
			d.log.Debugf("failed to get replica descriptor for replica %d: %s", replicaNum, err)
			continue
		}

		replicaPubKeyBytes, ok := desc.EnvelopeKeys[replicaEpoch]
		if !ok || len(replicaPubKeyBytes) == 0 {
			d.log.Debugf("replica public key not available for replica %d epoch %d", replicaNum, replicaEpoch)
			continue
		}

		replicaPubKey, err := replicaCommon.NikeScheme.UnmarshalBinaryPublicKey(replicaPubKeyBytes)
		if err != nil {
			d.log.Debugf("failed to unmarshal public key for replica %d: %s", replicaNum, err)
			continue
		}

		// Try to decrypt with this replica's public key
		rawInnerMsg, err = replicaCommon.MKEMNikeScheme.DecryptEnvelope(privateKey, replicaPubKey, env.Payload)
		if err == nil {
			d.log.Debugf("MKEM DECRYPT SUCCESS with replica %d: Decrypted %d bytes", replicaNum, len(rawInnerMsg))
			break
		}
		d.log.Debugf("MKEM DECRYPT failed with replica %d: %s", replicaNum, err)
	}

	if rawInnerMsg == nil {
		d.log.Errorf("MKEM DECRYPT FAILED with all possible replicas")
		return nil, fmt.Errorf("failed to decrypt envelope with any replica key")
	}

	d.log.Debugf("MKEM DECRYPT SUCCESS: Decrypted %d bytes", len(rawInnerMsg))
	innerMsg, err := pigeonhole.ParseReplicaMessageReplyInnerMessage(rawInnerMsg)
	if err != nil {
		d.log.Errorf("failed to unmarshal inner message: %s", err)
		return nil, fmt.Errorf("failed to unmarshal inner message: %s", err)
	}

	return innerMsg, nil
}

// ReplyHandlerParams groups parameters for reply handler functions (old API)
type ReplyHandlerParams struct {
	AppID       *[AppIDLength]byte
	MessageID   *[MessageIDLength]byte
	ChannelID   [thin.ChannelIDLength]byte
	ChannelDesc *ChannelDescriptor
	EnvHash     *[hash.HashSize]byte
	IsReader    bool
	IsWriter    bool
	Conn        *incomingConn
}

// NewReplyHandlerParams groups parameters for reply handler functions (new API)
type NewReplyHandlerParams struct {
	AppID       *[AppIDLength]byte
	MessageID   *[MessageIDLength]byte
	ChannelID   uint16
	ChannelDesc *ChannelDescriptor
	EnvHash     *[hash.HashSize]byte
	IsReader    bool
	IsWriter    bool
	Conn        *incomingConn
}

// handleReadReply processes a replica read reply
func (d *Daemon) handleReadReply(params *ReplyHandlerParams, readReply *pigeonhole.ReplicaReadReply) error {
	if !params.IsReader {
		d.log.Errorf("bug 4, invalid book keeping for channelID %x", params.ChannelID[:])
		return fmt.Errorf("bug 4, invalid book keeping for channelID %x", params.ChannelID[:])
	}

	if readReply.ErrorCode != 0 {
		d.log.Debugf("replica returned error code %d for read operation", readReply.ErrorCode)
		// Don't clean up envelope descriptors on replica errors - we want to retry with the same envelope
		return fmt.Errorf("replica read failed with error code %d", readReply.ErrorCode)
	}

	// Check if signature is all zeros (equivalent to nil check)
	var zeroSig [64]uint8
	if readReply.Signature == zeroSig {
		d.log.Debugf("replica returned zero signature for read operation")
		return fmt.Errorf("replica read reply has zero signature")
	}

	var boxid *[bacap.BoxIDSize]byte
	if params.MessageID != nil {
		params.ChannelDesc.StoredEnvelopesLock.RLock()
		storedData, exists := params.ChannelDesc.StoredEnvelopes[*params.MessageID]
		params.ChannelDesc.StoredEnvelopesLock.RUnlock()
		if exists {
			boxid = storedData.BoxID
			d.log.Debugf("Using stored box ID %x for message ID %x", boxid[:], params.MessageID[:])
		}
	}

	if boxid == nil {
		d.log.Errorf("No stored box ID found for message ID %x - cannot process reply", params.MessageID[:])
		return fmt.Errorf("no stored box ID found for message ID - cannot process reply")
	}

	d.log.Debugf("BACAP DECRYPT: Starting decryption for BoxID %x with payload size %d bytes", boxid[:], len(readReply.Payload))
	params.ChannelDesc.StatefulReaderLock.Lock()
	signature := (*[bacap.SignatureSize]byte)(readReply.Signature[:])
	innerplaintext, err := params.ChannelDesc.StatefulReader.DecryptNext(
		[]byte(constants.PIGEONHOLE_CTX),
		*boxid,
		readReply.Payload,
		*signature)
	params.ChannelDesc.StatefulReaderLock.Unlock()
	if err != nil {
		d.log.Errorf("BACAP DECRYPT FAILED for BoxID %x: %s", boxid[:], err)
		return fmt.Errorf("failed to decrypt next: %s", err)
	}

	d.log.Debugf("BACAP DECRYPT SUCCESS: Decrypted %d bytes for BoxID %x", len(innerplaintext), boxid[:])

	// Extract the original message from the padded payload (remove 4-byte length prefix and padding)
	originalMessage, err := pigeonhole.ExtractMessageFromPaddedPayload(innerplaintext)
	if err != nil {
		d.log.Errorf("Failed to extract message from padded payload: %s", err)
		return fmt.Errorf("failed to extract message from padded payload: %s", err)
	}

	d.log.Debugf("SENDING RESPONSE: MessageID %x, ChannelID %x, Payload size %d bytes (extracted from %d padded bytes)", params.MessageID[:], params.ChannelID[:], len(originalMessage), len(innerplaintext))
	err = params.Conn.sendResponse(&Response{
		AppID: params.AppID,
		ReadChannelReply: &thin.ReadChannelReply{
			MessageID: params.MessageID,
			ChannelID: params.ChannelID,
			Payload:   originalMessage,
		},
	})
	if err != nil {
		d.log.Errorf("Failed to send response to client: %s", err)
		// Don't clean up envelope descriptors if response sending failed - allow retry
		return fmt.Errorf("failed to send response to client: %s", err)
	}

	params.ChannelDesc.EnvelopeDescriptorsLock.Lock()
	delete(params.ChannelDesc.EnvelopeDescriptors, *params.EnvHash)
	params.ChannelDesc.EnvelopeDescriptorsLock.Unlock()

	// Also clean up stored envelope data if we have a message ID
	if params.MessageID != nil {
		params.ChannelDesc.StoredEnvelopesLock.Lock()
		delete(params.ChannelDesc.StoredEnvelopes, *params.MessageID)
		params.ChannelDesc.StoredEnvelopesLock.Unlock()
	}

	return nil
}

// handleCopyReply processes a copy command reply
func (d *Daemon) handleCopyReply(appid *[AppIDLength]byte, channelID [thin.ChannelIDLength]byte, copyReply *pigeonhole.CopyCommandReply, conn *incomingConn) error {
	var errMsg string
	if copyReply.ErrorCode != 0 {
		errMsg = fmt.Sprintf("copy command failed with error code %d", copyReply.ErrorCode)
		d.log.Errorf("copy command failed for channel %x with error code %d", channelID[:], copyReply.ErrorCode)
	} else {
		d.log.Debugf("copy command completed successfully for channel %x", channelID[:])
	}

	err := conn.sendResponse(&Response{
		AppID: appid,
		CopyChannelReply: &thin.CopyChannelReply{
			ChannelID: channelID,
			Err:       errMsg,
		},
	})
	if err != nil {
		d.log.Errorf("Failed to send copy response to client: %s", err)
		return fmt.Errorf("failed to send copy response to client: %s", err)
	}

	return nil
}

// handleWriteReply processes a replica write reply
func (d *Daemon) handleWriteReply(params *ReplyHandlerParams, writeReply *pigeonhole.ReplicaWriteReply) error {
	if !params.IsWriter {
		d.log.Errorf("bug 5, invalid book keeping for channelID %x", params.ChannelID[:])
		return fmt.Errorf("bug 5, invalid book keeping for channelID %x", params.ChannelID[:])
	}

	if writeReply.ErrorCode != 0 {
		d.log.Errorf("failed to write to channel, error code: %d", writeReply.ErrorCode)
	}

	err := params.Conn.sendResponse(&Response{
		AppID: params.AppID,
		WriteChannelReply: &thin.WriteChannelReply{
			ChannelID: params.ChannelID,
		},
	})
	if err != nil {
		d.log.Errorf("Failed to send write response to client: %s", err)
		// Don't clean up envelope descriptors if response sending failed - allow retry
		return fmt.Errorf("failed to send write response to client: %s", err)
	}

	params.ChannelDesc.EnvelopeDescriptorsLock.Lock()
	delete(params.ChannelDesc.EnvelopeDescriptors, *params.EnvHash)
	params.ChannelDesc.EnvelopeDescriptorsLock.Unlock()

	return nil
}

func (d *Daemon) send(request *Request) {
	var surbKey []byte
	var rtt time.Duration
	var err error
	var now time.Time

	if request.SendARQMessage != nil {
		request.SendARQMessage.SURBID = &[sphinxConstants.SURBIDLength]byte{}
		_, err = rand.Reader.Read(request.SendARQMessage.SURBID[:])
		if err != nil {
			panic(err)
		}
	}

	surbKey, rtt, err = d.client.SendCiphertext(request)
	if err != nil {
		d.log.Infof("SendCiphertext error: %s", err.Error())
	}

	if request.SendARQMessage != nil {
		d.log.Infof("ARQ RTT %s", rtt)
	}

	// Check if this is a request with SURB (either SendMessage or SendARQMessage)
	var withSURB bool
	var surbID *[sphinxConstants.SURBIDLength]byte
	var messageID *[MessageIDLength]byte
	var isLoopDecoy bool

	if request.SendMessage != nil {
		withSURB = request.SendMessage.WithSURB
		surbID = request.SendMessage.SURBID
		messageID = request.SendMessage.ID
		isLoopDecoy = (request.SendLoopDecoy != nil)
	} else if request.SendARQMessage != nil {
		withSURB = request.SendARQMessage.WithSURB
		surbID = request.SendARQMessage.SURBID
		messageID = request.SendARQMessage.ID
		isLoopDecoy = false
	}

	if withSURB {
		now = time.Now()
		// XXX  this is too aggressive, and must be at least the fetchInterval + rtt + some slopfactor to account for path delays

		fetchInterval := d.client.GetPollInterval()
		slop := time.Second
		duration := rtt + fetchInterval + slop
		replyArrivalTime := now.Add(duration)

		d.timerQueue.Push(uint64(replyArrivalTime.UnixNano()), surbID)

		if !isLoopDecoy {
			incomingConn := d.listener.getConnection(request.AppID)
			if incomingConn != nil {
				response := &Response{
					AppID: request.AppID,
					MessageSentEvent: &thin.MessageSentEvent{
						MessageID: messageID,
						SURBID:    surbID,
						SentAt:    now,
						ReplyETA:  rtt,
						Err:       err,
					},
				}
				err = incomingConn.sendResponse(response)
				if err != nil {
					d.log.Errorf("failed to send Response: %s", err)
				}
			}
		}
	}

	d.replyLock.Lock()
	if request.SendARQMessage != nil {
		message := &ARQMessage{
			AppID:              request.AppID,
			MessageID:          request.SendARQMessage.ID,
			SURBID:             request.SendARQMessage.SURBID,
			Payload:            request.SendARQMessage.Payload,
			DestinationIdHash:  request.SendARQMessage.DestinationIdHash,
			Retransmissions:    0,
			RecipientQueueID:   request.SendARQMessage.RecipientQueueID,
			SURBDecryptionKeys: surbKey,
			SentAt:             time.Now(),
			ReplyETA:           rtt,
		}

		d.arqSurbIDMap[*message.SURBID] = message
		myRtt := message.SentAt.Add(message.ReplyETA)
		myRtt = myRtt.Add(RoundTripTimeSlop)
		priority := uint64(myRtt.UnixNano())
		d.arqTimerQueue.Push(priority, message.SURBID)

		// ensure that we send the thin client an arq gc event so it cleans up it's arq specific book keeping
		slop := time.Minute * 5 // very conservative
		replyArrivalTime := time.Now().Add(rtt + slop)
		d.gcTimerQueue.Push(uint64(replyArrivalTime.UnixNano()), &gcReply{
			id:    request.SendARQMessage.ID,
			appID: request.AppID,
		})
	}

	if request.SendMessage != nil {
		// Check if this is a new API channel query (has ChannelID field)
		if request.SendMessage.ChannelID != nil {
			d.log.Infof("NEW API: Processing SendMessage with ChannelID %d, SURB ID %x",
				*request.SendMessage.ChannelID, request.SendMessage.SURBID[:8])

			d.log.Infof("NEW API: Storing SURB ID %x with Channel ID %d", request.SendMessage.SURBID[:8], *request.SendMessage.ChannelID)

			// New API: store in channel replies and new SURB ID map
			d.channelRepliesLock.Lock()
			d.channelReplies[*request.SendMessage.SURBID] = replyDescriptor{
				appID:   request.AppID,
				surbKey: surbKey,
			}
			d.channelRepliesLock.Unlock()

			// Store the SURB ID to channel ID mapping in the NEW API maps
			d.newSurbIDToChannelMapLock.Lock()
			d.newSurbIDToChannelMap[*request.SendMessage.SURBID] = *request.SendMessage.ChannelID
			d.newSurbIDToChannelMapLock.Unlock()

			d.log.Infof("NEW API: Stored SURB ID %x -> Channel ID %d mapping",
				request.SendMessage.SURBID[:8], *request.SendMessage.ChannelID)
		} else {
			// Old API: store in regular replies
			d.replies[*request.SendMessage.SURBID] = replyDescriptor{
				appID:   request.AppID,
				surbKey: surbKey,
			}
		}
		d.replyLock.Unlock()
		return
	}

	if isLoopDecoy {
		d.decoys[*surbID] = replyDescriptor{
			appID:   request.AppID,
			surbKey: surbKey,
		}
		d.replyLock.Unlock()
		return
	}
	d.replyLock.Unlock()
}

func (d *Daemon) sendLoopDecoy(request *Request) {
	// XXX FIXME consume statistics on our echo decoys for n-1 detection

	_, doc := d.client.CurrentDocument()
	if doc == nil {
		panic("doc is nil")
	}
	echoServices := common.FindServices(EchoService, doc)
	if len(echoServices) == 0 {
		panic("wtf no echo services")
	}
	echoService := echoServices[d.secureRand.Intn(len(echoServices))]

	serviceIdHash := hash.Sum256(echoService.MixDescriptor.IdentityKey)
	payload := make([]byte, d.client.geo.UserForwardPayloadLength)
	surbID := &[sphinxConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(surbID[:])
	if err != nil {
		panic(err)

	}

	// Convert to SendMessage for actual sending
	request.SendMessage = &thin.SendMessage{
		Payload:           payload,
		SURBID:            surbID,
		DestinationIdHash: &serviceIdHash,
		RecipientQueueID:  echoService.RecipientQueueID,
		WithSURB:          true,
	}

	d.send(request)
}

func (d *Daemon) sendDropDecoy() {
	_, doc := d.client.CurrentDocument()
	if doc == nil {
		panic("doc is nil")
	}
	echoServices := common.FindServices(EchoService, doc)
	if len(echoServices) == 0 {
		panic("wtf no echo services")
	}
	echoService := echoServices[d.secureRand.Intn(len(echoServices))]

	serviceIdHash := hash.Sum256(echoService.MixDescriptor.IdentityKey)
	payload := make([]byte, d.client.geo.UserForwardPayloadLength)

	request := &Request{
		SendMessage: &thin.SendMessage{
			WithSURB:          false,
			Payload:           payload,
			DestinationIdHash: &serviceIdHash,
			RecipientQueueID:  echoService.RecipientQueueID,
		},
	}

	d.send(request)
}

func (d *Daemon) arqResend(surbID *[sphinxConstants.SURBIDLength]byte) {
	select {
	case <-d.HaltCh():
		return
	case d.arqResendCh <- surbID:
	default:
		// If we can't send immediately and we're not halted,
		// the channel might be full or the receiver is busy.
		// Don't block during shutdown.
		d.log.Debugf("ARQ resend channel full, dropping resend for SURB ID %x", surbID[:])
	}
}

func (d *Daemon) arqDoResend(surbID *[sphinxConstants.SURBIDLength]byte) {
	defer d.log.Info("resend end")

	d.replyLock.Lock()
	message, ok := d.arqSurbIDMap[*surbID]

	// NOTE(david): if the arqSurbIDMap entry is not found
	// it means that HandleAck was already called with the
	// given SURB ID.
	if !ok {
		d.log.Warningf("SURB ID %x NOT FOUND. Aborting resend.", surbID[:])
		d.replyLock.Unlock()
		return
	}
	if (message.Retransmissions + 1) > MaxRetransmissions {
		d.log.Warning("ARQ Max retries met.")
		response := &Response{
			AppID: message.AppID,
			MessageReplyEvent: &thin.MessageReplyEvent{
				MessageID: message.MessageID,
				Err:       errors.New("max retries met"),
				Payload:   []byte{},
				SURBID:    surbID,
			},
		}
		incomingConn := d.listener.getConnection(message.AppID)
		if incomingConn == nil {
			panic("incomingConn is nil")
		}
		err := incomingConn.sendResponse(response)
		if err != nil {
			d.log.Warningf("failed to send MessageReplyEvent with max retry failure")
		}
		d.replyLock.Unlock()
		return
	}
	d.log.Warningf("resend ----------------- REMOVING SURB ID %x", surbID[:])
	delete(d.arqSurbIDMap, *surbID)

	newsurbID := &[sphinxConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(newsurbID[:])
	if err != nil {
		panic(err)
	}
	pkt, k, rtt, err := d.client.ComposeSphinxPacket(&Request{
		AppID: message.AppID,
		SendARQMessage: &thin.SendARQMessage{
			ID:                message.MessageID,
			WithSURB:          true,
			DestinationIdHash: message.DestinationIdHash,
			RecipientQueueID:  message.RecipientQueueID,
			Payload:           message.Payload,
			SURBID:            newsurbID,
		},
	})
	if err != nil {
		d.log.Errorf("failed to send sphinx packet: %s", err.Error())
	}

	message.SURBID = newsurbID
	message.SURBDecryptionKeys = k
	message.ReplyETA = rtt
	message.SentAt = time.Now()
	message.Retransmissions += 1
	d.arqSurbIDMap[*newsurbID] = message
	d.replyLock.Unlock()

	d.log.Warningf("resend PUTTING INTO MAP, NEW SURB ID %x", newsurbID[:])
	myRtt := message.SentAt.Add(message.ReplyETA)
	myRtt = myRtt.Add(RoundTripTimeSlop)
	priority := uint64(myRtt.UnixNano())
	d.arqTimerQueue.Push(priority, newsurbID)

	err = d.client.SendPacket(pkt)
	if err != nil {
		d.log.Warningf("ARQ resend failure: %s", err)
	}
}

func (d *Daemon) copyChannel(request *Request) {
	channelID := request.CopyChannel.ChannelID

	// Hold channelMapLock for the entire operation to ensure channelDesc doesn't change
	d.channelMapLock.RLock()
	channelDesc, ok := d.channelMap[channelID]
	if !ok {
		d.channelMapLock.RUnlock()
		d.log.Errorf("copyChannel failure: no channel found for channelID %x", channelID[:])
		d.sendCopyChannelErrorResponse(request, channelID, "channel not found")
		return
	}
	// Keep the lock held while we work with channelDesc
	defer d.channelMapLock.RUnlock()

	// Ensure this is a write channel
	if channelDesc.StatefulWriter == nil {
		d.log.Errorf("copyChannel failure: channel %x is not a write channel", channelID[:])
		d.sendCopyChannelErrorResponse(request, channelID, "channel is not a write channel")
		return
	}

	_, doc := d.client.CurrentDocument()
	if doc == nil {
		d.log.Errorf("copyChannel failure: no PKI document available")
		d.sendCopyChannelErrorResponse(request, channelID, "no PKI document available")
		return
	}

	// Extract the WriteCap from the channel descriptor
	channelDesc.StatefulWriterLock.Lock()
	writeCap := channelDesc.StatefulWriter.Wcap
	channelDesc.StatefulWriterLock.Unlock()

	// Create the CopyCommand
	writeCapBytes, err := writeCap.MarshalBinary()
	if err != nil {
		d.log.Errorf("failed to marshal WriteCap: %s", err)
		return
	}
	copyCommand := &pigeonhole.CopyCommand{
		WriteCapLen: uint32(len(writeCapBytes)),
		WriteCap:    writeCapBytes,
	}

	// Create CourierQuery with CopyCommand
	courierQuery := &pigeonhole.CourierQuery{
		QueryType:   1, // 1 = copy_command
		CopyCommand: copyCommand,
	}

	// Generate SURB ID
	surbid := &[sphinxConstants.SURBIDLength]byte{}
	_, err = rand.Reader.Read(surbid[:])
	if err != nil {
		d.log.Errorf("copyChannel failure: failed to generate SURB ID: %s", err)
		d.sendCopyChannelErrorResponse(request, channelID, "failed to generate SURB ID")
		return
	}

	// Get random courier
	destinationIdHash, recipientQueueID := GetRandomCourier(doc)

	// Create send request
	sendRequest := &Request{
		AppID: request.AppID,
		SendMessage: &thin.SendMessage{
			WithSURB:          true,
			DestinationIdHash: destinationIdHash,
			RecipientQueueID:  recipientQueueID,
			Payload:           courierQuery.Bytes(),
			SURBID:            surbid,
		},
	}

	// Send to courier
	surbKey, rtt, err := d.client.SendCiphertext(sendRequest)
	if err != nil {
		d.log.Errorf("copyChannel failure: failed to send to courier: %s", err)
		d.sendCopyChannelErrorResponse(request, channelID, err.Error())
		return
	}

	// Set up reply handling
	fetchInterval := d.client.GetPollInterval()
	slop := time.Second
	duration := rtt + fetchInterval + slop
	replyArrivalTime := time.Now().Add(duration)

	d.channelRepliesLock.Lock()
	d.channelReplies[*surbid] = replyDescriptor{
		ID:      request.CopyChannel.ID,
		appID:   request.AppID,
		surbKey: surbKey,
	}
	d.channelRepliesLock.Unlock()

	d.surbIDToChannelMapLock.Lock()
	d.surbIDToChannelMap[*surbid] = channelID
	d.surbIDToChannelMapLock.Unlock()

	d.timerQueue.Push(uint64(replyArrivalTime.UnixNano()), surbid)

	d.log.Debugf("copyChannel: sent copy command for channel %x", channelID[:])
}

func (d *Daemon) sendCopyChannelErrorResponse(request *Request, channelID [thin.ChannelIDLength]byte, errMsg string) {
	conn := d.listener.getConnection(request.AppID)
	if conn != nil {
		conn.sendResponse(&Response{
			AppID: request.AppID,
			CopyChannelReply: &thin.CopyChannelReply{
				ChannelID: channelID,
				Err:       errMsg,
			},
		})
	}
}

// handleOldChannelReply handles channel replies for the old API
func (d *Daemon) handleOldChannelReply(appid *[AppIDLength]byte,
	mesgID *[MessageIDLength]byte,
	surbid *[sphinxConstants.SURBIDLength]byte,
	plaintext []byte,
	conn *incomingConn,
	channelID [thin.ChannelIDLength]byte,
	channelDesc *ChannelDescriptor) error {

	isReader, isWriter, err := d.validateChannel(channelID, channelDesc)
	if err != nil {
		return err
	}

	// First, parse the courier query reply to check what type of reply it is
	courierQueryReply, err := pigeonhole.ParseCourierQueryReply(plaintext)
	if err != nil {
		d.log.Errorf("failed to unmarshal courier query reply: %s", err)
		return fmt.Errorf("failed to unmarshal courier query reply: %s", err)
	}

	// Handle copy command replies
	if courierQueryReply.CopyCommandReply != nil {
		return d.handleCopyReply(appid, channelID, courierQueryReply.CopyCommandReply, conn)
	}

	// Handle envelope replies (read/write operations)
	if courierQueryReply.EnvelopeReply != nil {
		env, envelopeDesc, privateKey, err := d.processEnvelopeReply(courierQueryReply.EnvelopeReply, channelDesc)
		if err != nil {
			return err
		}

		innerMsg, err := d.decryptMKEMEnvelope(env, envelopeDesc, privateKey)
		if err != nil {
			return err
		}

		envHash := (*[hash.HashSize]byte)(env.EnvelopeHash[:])

		switch {
		case innerMsg.ReadReply != nil:
			params := &ReplyHandlerParams{
				AppID:       appid,
				MessageID:   mesgID,
				ChannelID:   channelID,
				ChannelDesc: channelDesc,
				EnvHash:     envHash,
				IsReader:    isReader,
				IsWriter:    isWriter,
				Conn:        conn,
			}
			return d.handleReadReply(params, innerMsg.ReadReply)
		case innerMsg.WriteReply != nil:
			params := &ReplyHandlerParams{
				AppID:       appid,
				MessageID:   mesgID,
				ChannelID:   channelID,
				ChannelDesc: channelDesc,
				EnvHash:     envHash,
				IsReader:    isReader,
				IsWriter:    isWriter,
				Conn:        conn,
			}
			return d.handleWriteReply(params, innerMsg.WriteReply)
		}
		d.log.Errorf("bug 6, invalid book keeping for channelID %x", channelID[:])
		return fmt.Errorf("bug 6, invalid book keeping for channelID %x", channelID[:])
	}

	d.log.Errorf("courier query reply contains neither envelope reply nor copy command reply")
	return fmt.Errorf("courier query reply contains neither envelope reply nor copy command reply")
}

// validateNewChannel performs sanity checks on the channel descriptor and determines channel type (new API)
func (d *Daemon) validateNewChannel(channelID uint16, channelDesc *ChannelDescriptor) (bool, bool, error) {
	// sanity check
	if channelDesc.StatefulReader == nil && channelDesc.StatefulWriter == nil {
		d.log.Errorf("bug 1, invalid book keeping for channelID %d", channelID)
		return false, false, fmt.Errorf("bug 1, invalid book keeping for channelID %d", channelID)
	}
	if channelDesc.StatefulReader != nil && channelDesc.StatefulWriter != nil {
		d.log.Errorf("bug 2, invalid book keeping for channelID %d", channelID)
		return false, false, fmt.Errorf("bug 2, invalid book keeping for channelID %d", channelID)
	}
	if channelDesc.EnvelopeDescriptors == nil {
		d.log.Errorf("bug 3, invalid book keeping for channelID %d", channelID)
		return false, false, fmt.Errorf("bug 3, invalid book keeping for channelID %d", channelID)
	}

	isReader := channelDesc.StatefulReader != nil
	isWriter := channelDesc.StatefulWriter != nil
	return isReader, isWriter, nil
}

// handleNewCopyReply processes a copy command reply (new API)
func (d *Daemon) handleNewCopyReply(appid *[AppIDLength]byte, channelID uint16, copyReply *pigeonhole.CopyCommandReply, conn *incomingConn) error {
	var errMsg string
	if copyReply.ErrorCode != 0 {
		errMsg = fmt.Sprintf("copy command failed with error code %d", copyReply.ErrorCode)
		d.log.Errorf("copy command failed for channel %d with error code %d", channelID, copyReply.ErrorCode)
	} else {
		d.log.Debugf("copy command completed successfully for channel %d", channelID)
	}

	err := conn.sendResponse(&Response{
		AppID: appid,
		CopyChannelReply: &thin.CopyChannelReply{
			ChannelID: [thin.ChannelIDLength]byte{}, // TODO: Convert uint16 to byte array if needed
			Err:       errMsg,
		},
	})
	if err != nil {
		d.log.Errorf("Failed to send copy response to client: %s", err)
		return fmt.Errorf("failed to send copy response to client: %s", err)
	}

	return nil
}

// handleNewReadReply processes a read reply (new API)
func (d *Daemon) handleNewReadReply(params *NewReplyHandlerParams, readReply *pigeonhole.ReplicaReadReply) error {
	if !params.IsReader {
		d.log.Errorf("bug 4, invalid book keeping for channelID %d", params.ChannelID)
		return fmt.Errorf("bug 4, invalid book keeping for channelID %d", params.ChannelID)
	}

	var replyErr error
	var payload []byte

	if readReply.ErrorCode != 0 {
		replyErr = fmt.Errorf("read failed with error code %d", readReply.ErrorCode)
		d.log.Errorf("read failed for channel %d with error code %d", params.ChannelID, readReply.ErrorCode)
	} else {
		// Check if signature is all zeros (equivalent to nil check)
		var zeroSig [64]uint8
		if readReply.Signature == zeroSig {
			replyErr = fmt.Errorf("replica read reply has zero signature")
			d.log.Debugf("replica returned zero signature for read operation")
		} else {
			// For new API, get the next BoxID from the StatefulReader
			params.ChannelDesc.StatefulReaderLock.Lock()
			boxid, err := params.ChannelDesc.StatefulReader.NextBoxID()
			if err != nil {
				params.ChannelDesc.StatefulReaderLock.Unlock()
				replyErr = fmt.Errorf("failed to get next box ID: %s", err)
				d.log.Errorf("Failed to get next box ID for channel %d: %s", params.ChannelID, err)
			} else {
				// BACAP decrypt the payload
				d.log.Debugf("BACAP DECRYPT: Starting decryption for BoxID %x with payload size %d bytes", boxid[:], len(readReply.Payload))
				signature := (*[bacap.SignatureSize]byte)(readReply.Signature[:])
				innerplaintext, err := params.ChannelDesc.StatefulReader.DecryptNext(
					[]byte(constants.PIGEONHOLE_CTX),
					*boxid,
					readReply.Payload,
					*signature)
				params.ChannelDesc.StatefulReaderLock.Unlock()

				if err != nil {
					replyErr = fmt.Errorf("failed to decrypt next: %s", err)
					d.log.Errorf("BACAP DECRYPT FAILED for BoxID %x: %s", boxid[:], err)
				} else {
					d.log.Debugf("BACAP DECRYPT SUCCESS: Decrypted %d bytes for BoxID %x", len(innerplaintext), boxid[:])

					// Extract the original message from the padded payload
					originalMessage, err := pigeonhole.ExtractMessageFromPaddedPayload(innerplaintext)
					if err != nil {
						replyErr = fmt.Errorf("failed to extract message from padded payload: %s", err)
						d.log.Errorf("Failed to extract message from padded payload: %s", err)
					} else {
						payload = originalMessage
						d.log.Debugf("Successfully extracted %d bytes from %d padded bytes for channel %d", len(originalMessage), len(innerplaintext), params.ChannelID)
					}
				}
			}
		}
	}

	// For new API, use MessageReplyEvent to deliver the read result
	err := params.Conn.sendResponse(&Response{
		AppID: params.AppID,
		MessageReplyEvent: &thin.MessageReplyEvent{
			MessageID: params.MessageID,
			Payload:   payload,
			Err:       replyErr,
		},
	})
	if err != nil {
		d.log.Errorf("Failed to send read response to client: %s", err)
		return fmt.Errorf("failed to send read response to client: %s", err)
	}

	return nil
}

// handleNewWriteReply processes a write reply (new API)
func (d *Daemon) handleNewWriteReply(params *NewReplyHandlerParams, writeReply *pigeonhole.ReplicaWriteReply) error {
	if !params.IsWriter {
		d.log.Errorf("bug 5, invalid book keeping for channelID %d", params.ChannelID)
		return fmt.Errorf("bug 5, invalid book keeping for channelID %d", params.ChannelID)
	}

	var replyErr error
	if writeReply.ErrorCode != 0 {
		replyErr = fmt.Errorf("write failed with error code %d", writeReply.ErrorCode)
		d.log.Errorf("NEW API WRITE FAILED: Channel %d, Error Code %d", params.ChannelID, writeReply.ErrorCode)
	} else {
		d.log.Infof("NEW API WRITE SUCCESS: Channel %d completed successfully", params.ChannelID)
	}

	// For new API, use MessageReplyEvent to deliver the write result
	err := params.Conn.sendResponse(&Response{
		AppID: params.AppID,
		MessageReplyEvent: &thin.MessageReplyEvent{
			MessageID: params.MessageID,
			Err:       replyErr,
		},
	})
	if err != nil {
		d.log.Errorf("Failed to send write response to client: %s", err)
		return fmt.Errorf("failed to send write response to client: %s", err)
	}

	return nil
}
