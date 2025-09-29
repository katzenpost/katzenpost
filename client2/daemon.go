// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"crypto/hmac"
	"crypto/rand"
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

// ReplyHandlerParams groups parameters for reply handler functions
type ReplyHandlerParams struct {
	AppID       *[AppIDLength]byte
	MessageID   *[MessageIDLength]byte
	ChannelID   uint16
	ChannelDesc *ChannelDescriptor
	EnvHash     *[hash.HashSize]byte
	IsReader    bool
	IsWriter    bool
	ReplyIndex  uint8
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

	// Channel reply tracking (used by both old and new API)
	channelReplies     map[[sphinxConstants.SURBIDLength]byte]replyDescriptor
	channelRepliesLock *sync.RWMutex

	// Channel management (new API)
	newSurbIDToChannelMap     map[[sphinxConstants.SURBIDLength]byte]uint16
	newSurbIDToChannelMapLock *sync.RWMutex
	newChannelMap             map[uint16]*ChannelDescriptor
	newChannelMapLock         *sync.RWMutex
	newChannelMapXXX          map[uint16]bool
	newChannelMapXXXLock      *sync.RWMutex

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
		// Channel reply tracking
		channelReplies:     make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		channelRepliesLock: new(sync.RWMutex),
		// Channel management (new API)
		newSurbIDToChannelMap:     make(map[[sphinxConstants.SURBIDLength]byte]uint16),
		newSurbIDToChannelMapLock: new(sync.RWMutex),
		newChannelMap:             make(map[uint16]*ChannelDescriptor),
		newChannelMapLock:         new(sync.RWMutex),
		newChannelMapXXX:          make(map[uint16]bool),
		newChannelMapXXXLock:      new(sync.RWMutex),
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
	d.newChannelMapXXXLock.Lock()
	defer d.newChannelMapXXXLock.Unlock()

	for {
		channelID := uint16(hpqcRand.NewMath().Intn(65535) + 1) // [1, 65535]

		if _, exists := d.newChannelMapXXX[channelID]; !exists {
			d.newChannelMapXXX[channelID] = true // reserve it
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

// Shutdown cleanly shuts down a given Server instance.
func (d *Daemon) Shutdown() {
	d.haltOnce.Do(func() { d.halt() })
}

func (d *Daemon) halt() {
	shutdownStart := time.Now()
	d.log.Info("Starting graceful daemon shutdown")

	// Step 1: Stop listener
	listenerStart := time.Now()
	d.log.Debug("Stopping thin client listener")
	d.listener.Shutdown()
	d.log.Infof("Listener stopped in %v", time.Since(listenerStart))

	// Step 2: Stop workers
	workersStart := time.Now()
	d.log.Debug("Stopping workers first to prevent channel deadlocks")
	d.Halt() // shutdown ingressWorker and egressWorker first
	d.log.Infof("Workers stopped in %v", time.Since(workersStart))

	// Step 3: Parallelize timer queue shutdown for faster shutdown
	timerStart := time.Now()
	d.log.Debug("Stopping timer queues in parallel")
	var timerWg sync.WaitGroup
	timerWg.Add(3)

	go func() {
		defer timerWg.Done()
		start := time.Now()
		d.log.Debug("Stopping timerQueue")
		d.timerQueue.Halt()
		d.log.Debugf("timerQueue stopped in %v", time.Since(start))
	}()

	go func() {
		defer timerWg.Done()
		start := time.Now()
		d.log.Debug("Stopping gcTimerQueue")
		d.gcTimerQueue.Halt()
		d.log.Debugf("gcTimerQueue stopped in %v", time.Since(start))
	}()

	go func() {
		defer timerWg.Done()
		start := time.Now()
		d.log.Debug("Stopping arqTimerQueue")
		d.arqTimerQueue.Halt()
		d.log.Debugf("arqTimerQueue stopped in %v", time.Since(start))
	}()

	timerWg.Wait()
	d.log.Infof("All timer queues stopped in %v", time.Since(timerStart))

	// Step 4: Stop client
	clientStart := time.Now()
	d.log.Debug("Stopping client")
	d.client.Shutdown()
	d.log.Infof("Client stopped in %v", time.Since(clientStart))

	d.log.Infof("Daemon shutdown complete in %v", time.Since(shutdownStart))
}

func (d *Daemon) Start() error {
	var err error
	rates := &Rates{}
	if d.cfg.CachedDocument != nil {
		rates = ratesFromPKIDoc(d.cfg.CachedDocument)
	}

	d.client, err = New(d.cfg, d.logbackend)
	if err != nil {
		return err
	}

	d.listener, err = NewListener(d.client, rates, d.egressCh, d.logbackend, d.cleanupChannelsForAppID)
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
		surbID, ok := rawSurbID.(*[sphinxConstants.SURBIDLength]byte)
		if !ok {
			panic("wtf, failed type assertion!")
		}
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

			case request.SendChannelQuery != nil:
				d.sendChannelQuery(request)
			case request.CreateWriteChannel != nil:
				d.createWriteChannel(request)
			case request.CreateReadChannel != nil:
				d.createReadChannel(request)
			case request.WriteChannel != nil:
				d.writeChannel(request)
			case request.ResumeWriteChannel != nil:
				d.resumeWriteChannel(request)
			case request.ResumeWriteChannelQuery != nil:
				d.resumeWriteChannelQuery(request)
			case request.ReadChannel != nil:
				d.readChannel(request)
			case request.ResumeReadChannel != nil:
				d.resumeReadChannel(request)
			case request.ResumeReadChannelQuery != nil:
				d.resumeReadChannelQuery(request)
			case request.CloseChannel != nil:
				d.closeChannel(request)

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

	// Debug logging for channel reply lookup
	if isChannelReply {
		if myChannelReplyDescriptor.ID != nil {
			d.log.Errorf("DEBUG: Found channel reply descriptor with MessageID %x for SURBID %x", myChannelReplyDescriptor.ID[:8], reply.surbID[:8])
		} else {
			d.log.Errorf("DEBUG: WARNING: Found channel reply descriptor with nil MessageID for SURBID %x", reply.surbID[:8])
		}
	}

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

	surbPayload, err := d.client.sphinx.DecryptSURBPayload(reply.ciphertext, desc.surbKey)
	if err != nil {
		d.log.Debugf("SURB reply decryption error: %s", err.Error())
		return
	}

	// XXX FIXME consume statistics on our loop decoys for n-1 detection
	if isDecoy {
		return
	}

	if isChannelReply {
		err := d.handleChannelReply(desc.appID, desc.ID, reply.surbID, surbPayload)
		if err != nil {
			d.log.Errorf("BUG!Failed to handle channel reply: %s", err)

			// send error code back to client
			conn := d.listener.getConnection(desc.appID)
			if conn == nil {
				d.log.Errorf("no connection associated with AppID %x", desc.appID[:])
				return
			}
			err := conn.sendResponse(&Response{
				AppID: desc.appID,
				ChannelQueryReplyEvent: &thin.ChannelQueryReplyEvent{
					MessageID: desc.ID,
					ErrorCode: thin.ThinClientErrorInternalError,
				},
			})
			if err != nil {
				d.log.Errorf("failed to send error response to client: %s", err)
			}
		}

		d.channelRepliesLock.Lock()
		delete(d.channelReplies, *reply.surbID)
		d.channelRepliesLock.Unlock()

		d.newSurbIDToChannelMapLock.Lock()
		delete(d.newSurbIDToChannelMap, *reply.surbID)
		d.newSurbIDToChannelMapLock.Unlock()
	} else {
		// not a reply to a channel operation,
		// thei is legacy API
		conn := d.listener.getConnection(desc.appID)
		if conn == nil {
			d.log.Errorf("no connection associated with AppID %x", desc.appID[:])
			return
		}
		conn.sendResponse(&Response{
			AppID: desc.appID,
			MessageReplyEvent: &thin.MessageReplyEvent{
				MessageID: desc.ID,
				SURBID:    reply.surbID,
				Payload:   surbPayload,
				ErrorCode: thin.ThinClientSuccess, // No error
			},
		})
	}
}

func (d *Daemon) validateResumeWriteChannelRequest(request *Request) error {
	if request.ResumeWriteChannel.QueryID == nil {
		return fmt.Errorf("QueryID cannot be nil when resuming an existing channel")
	}
	if request.ResumeWriteChannel.WriteCap == nil {
		return fmt.Errorf("WriteCap cannot be nil when resuming an existing channel")
	}
	// Note(David): The rest of the fields are optional.
	return nil
}

func (d *Daemon) validateResumeWriteChannelQueryRequest(request *Request) error {
	if request.ResumeWriteChannelQuery.QueryID == nil {
		return fmt.Errorf("QueryID cannot be nil when resuming an existing channel")
	}
	if request.ResumeWriteChannelQuery.WriteCap == nil {
		return fmt.Errorf("WriteCap cannot be nil when resuming an existing channel")
	}
	if request.ResumeWriteChannelQuery.MessageBoxIndex == nil {
		return fmt.Errorf("MessageBoxIndex cannot be nil when resuming an existing channel")
	}
	if request.ResumeWriteChannelQuery.EnvelopeDescriptor == nil {
		return fmt.Errorf("EnvelopeDescriptor cannot be nil when resuming an existing channel")
	}
	if request.ResumeWriteChannelQuery.EnvelopeHash == nil {
		return fmt.Errorf("EnvelopeHash cannot be nil when resuming an existing channel")
	}
	return nil
}

func (d *Daemon) resumeWriteChannel(request *Request) {
	// validate request
	if err := d.validateResumeWriteChannelRequest(request); err != nil {
		d.log.Errorf("BUG, invalid request: %v", err)
		d.sendResumeWriteChannelError(request, thin.ThinClientErrorInternalError)
		return
	}

	// set used write cap map entry
	_, err := request.ResumeWriteChannel.WriteCap.MarshalBinary()
	if err != nil {
		d.log.Errorf("BUG, failed to marshal write cap: %v", err)
		d.sendResumeWriteChannelError(request, thin.ThinClientImpossibleHashError)
		return
	}
	//writeCapHash := hash.Sum256(writeCapBlob)
	//d.capabilityLock.Lock()
	//_, ok := d.usedWriteCaps[writeCapHash]
	//if ok {
	//	d.log.Errorf("BUG, write cap already in use")
	//	d.capabilityLock.Unlock()
	//	d.sendResumeWriteChannelError(request, thin.ThinClientCapabilityAlreadyInUse)
	//	return
	//}
	//d.usedWriteCaps[writeCapHash] = true
	//d.capabilityLock.Unlock()

	// use fields from the request to mutate our current state
	channelID := d.generateUniqueChannelID()
	var statefulWriter *bacap.StatefulWriter
	if request.ResumeWriteChannel.MessageBoxIndex == nil {
		statefulWriter, err = bacap.NewStatefulWriter(request.ResumeWriteChannel.WriteCap, constants.PIGEONHOLE_CTX)
		if err != nil {
			d.log.Errorf("BUG, failed to create stateful writer: %v", err)
			d.sendResumeWriteChannelError(request, thin.ThinClientErrorInternalError)
			return
		}
	} else {
		statefulWriter, err = bacap.NewStatefulWriterWithIndex(request.ResumeWriteChannel.WriteCap, constants.PIGEONHOLE_CTX, request.ResumeWriteChannel.MessageBoxIndex)
		if err != nil {
			d.log.Errorf("BUG, failed to create stateful writer: %v", err)
			d.sendResumeWriteChannelError(request, thin.ThinClientErrorInternalError)
			return
		}
	}

	myNewChannelDescriptor := &ChannelDescriptor{
		AppID:               request.AppID,
		StatefulWriter:      statefulWriter,
		EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
	}

	d.newChannelMapLock.Lock()
	d.newChannelMap[channelID] = myNewChannelDescriptor
	d.newChannelMapLock.Unlock()

	// send reply back to client
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf("no connection associated with AppID %x", request.AppID[:])
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		ResumeWriteChannelReply: &thin.ResumeWriteChannelReply{
			QueryID:   request.ResumeWriteChannel.QueryID,
			ChannelID: channelID,
			ErrorCode: thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) resumeWriteChannelQuery(request *Request) {
	// validate request
	if err := d.validateResumeWriteChannelQueryRequest(request); err != nil {
		d.log.Errorf("BUG, invalid request: %v", err)
		d.sendResumeWriteChannelQueryError(request, thin.ThinClientErrorInternalError)
		return
	}

	// set used write cap map entry
	_, err := request.ResumeWriteChannelQuery.WriteCap.MarshalBinary()
	if err != nil {
		d.log.Errorf("BUG, failed to marshal write cap: %v", err)
		d.sendResumeWriteChannelQueryError(request, thin.ThinClientImpossibleHashError)
		return
	}
	//writeCapHash := hash.Sum256(writeCapBlob)
	//d.capabilityLock.Lock()
	//_, ok := d.usedWriteCaps[writeCapHash]
	//if ok {
	//	d.log.Errorf("BUG, write cap already in use")
	//	d.capabilityLock.Unlock()
	//	d.sendResumeWriteChannelQueryError(request, thin.ThinClientCapabilityAlreadyInUse)
	//	return
	//}
	//d.usedWriteCaps[writeCapHash] = true
	//d.capabilityLock.Unlock()

	// use fields from the request to mutate our current state
	channelID := d.generateUniqueChannelID()
	var statefulWriter *bacap.StatefulWriter
	statefulWriter, err = bacap.NewStatefulWriterWithIndex(request.ResumeWriteChannelQuery.WriteCap, constants.PIGEONHOLE_CTX, request.ResumeWriteChannelQuery.MessageBoxIndex)
	if err != nil {
		d.log.Errorf("BUG, failed to create stateful writer: %v", err)
		d.sendResumeWriteChannelQueryError(request, thin.ThinClientErrorInternalError)
		return
	}

	myNewChannelDescriptor := &ChannelDescriptor{
		AppID:               request.AppID,
		StatefulWriter:      statefulWriter,
		EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
	}

	// handle optional fields which are only used for resumption of a previously prepared write query blob
	// store envelope descriptor for later use
	envelopeDesc, err := EnvelopeDescriptorFromBytes(request.ResumeWriteChannelQuery.EnvelopeDescriptor)
	if err != nil {
		// 20:40:22.483 ERRO katzenpost/client2: resumeWriteChannelQuery: Failed to parse envelope descriptor: cbor: 1999 bytes of extraneous data starting at index 1
		//
		d.log.Errorf("resumeWriteChannelQuery: Failed to parse envelope descriptor: %v", err)
		d.sendResumeWriteChannelQueryError(request, thin.ThinClientErrorInvalidRequest)
		return
	}
	envHash := request.ResumeWriteChannelQuery.EnvelopeHash
	myNewChannelDescriptor.EnvelopeDescriptors[*envHash] = envelopeDesc

	d.newChannelMapLock.Lock()
	d.newChannelMap[channelID] = myNewChannelDescriptor
	d.newChannelMapLock.Unlock()

	// send reply back to client
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf("no connection associated with AppID %x", request.AppID[:])
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		ResumeWriteChannelQueryReply: &thin.ResumeWriteChannelQueryReply{
			QueryID:   request.ResumeWriteChannelQuery.QueryID,
			ChannelID: channelID,
			ErrorCode: thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) sendResumeWriteChannelQueryError(request *Request, errorCode uint8) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf("no connection associated with AppID %x", request.AppID[:])
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		ResumeWriteChannelQueryReply: &thin.ResumeWriteChannelQueryReply{
			QueryID:   request.ResumeWriteChannelQuery.QueryID,
			ErrorCode: errorCode,
		},
	})
}

func (d *Daemon) sendResumeWriteChannelError(request *Request, errorCode uint8) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf("no connection associated with AppID %x", request.AppID[:])
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		ResumeWriteChannelReply: &thin.ResumeWriteChannelReply{
			QueryID:   request.ResumeWriteChannel.QueryID,
			ErrorCode: errorCode,
		},
	})
}

func (d *Daemon) validateResumeReadChannelRequest(request *Request) error {
	if request.ResumeReadChannel.QueryID == nil {
		return fmt.Errorf("queryID cannot be nil")
	}
	if request.ResumeReadChannel.ReadCap == nil {
		return fmt.Errorf("readCap cannot be nil")
	}
	return nil
}

func (d *Daemon) validateResumeReadChannelQueryRequest(request *Request) error {
	if request.ResumeReadChannelQuery.QueryID == nil {
		return fmt.Errorf("queryID cannot be nil")
	}
	if request.ResumeReadChannelQuery.ReadCap == nil {
		return fmt.Errorf("readCap cannot be nil")
	}
	if request.ResumeReadChannelQuery.NextMessageIndex == nil {
		return fmt.Errorf("nextMessageIndex cannot be nil")
	}
	if request.ResumeReadChannelQuery.EnvelopeDescriptor == nil {
		return fmt.Errorf("envelopeDescriptor cannot be nil")
	}
	if request.ResumeReadChannelQuery.EnvelopeHash == nil {
		return fmt.Errorf("envelopeHash cannot be nil")
	}
	return nil
}

func (d *Daemon) resumeReadChannel(request *Request) {
	// NOTE(David):
	// handle the request in several steps:
	// 1. validate request
	// 2. set used read cap map entry
	// 3. create new channel descriptor
	// 4. inspect optional request fields that are only used for resumption of a previously prepared read query blob

	err := d.validateResumeReadChannelRequest(request)
	if err != nil {
		d.log.Errorf("BUG, invalid request: %v", err)
		d.sendResumeReadChannelError(request, thin.ThinClientErrorInvalidResumeReadChannelRequest)
		return
	}

	_, err = request.ResumeReadChannel.ReadCap.MarshalBinary()
	if err != nil {
		d.log.Errorf("BUG, failed to marshal read cap: %v", err)
		d.sendResumeReadChannelError(request, thin.ThinClientErrorInternalError)
		return
	}
	//readCapHash := hash.Sum256(readCapBlob)

	//d.capabilityLock.Lock()
	//_, ok := d.usedReadCaps[readCapHash]
	//if ok {
	//	d.log.Errorf("BUG, read cap already in use")
	//	d.sendResumeReadChannelError(request, thin.ThinClientCapabilityAlreadyInUse)
	//	d.capabilityLock.Unlock()
	//	return
	//}
	//d.usedReadCaps[readCapHash] = true
	//d.capabilityLock.Unlock()

	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf("no connection associated with AppID %x", request.AppID[:])
		d.sendResumeReadChannelError(request, thin.ThinClientErrorConnectionLost)
		return
	}
	channelID := d.generateUniqueChannelID()
	var statefulReader *bacap.StatefulReader
	if request.ResumeReadChannel.NextMessageIndex == nil {
		statefulReader, err = bacap.NewStatefulReader(request.ResumeReadChannel.ReadCap, constants.PIGEONHOLE_CTX)
		if err != nil {
			d.log.Errorf("BUG, failed to create stateful reader: %v", err)
			d.sendResumeReadChannelError(request, thin.ThinClientErrorInternalError)
			return
		}
	} else {
		statefulReader, err = bacap.NewStatefulReaderWithIndex(request.ResumeReadChannel.ReadCap, constants.PIGEONHOLE_CTX, request.ResumeReadChannel.NextMessageIndex)
		if err != nil {
			d.log.Errorf("BUG, failed to create stateful reader: %v", err)
			d.sendResumeReadChannelError(request, thin.ThinClientErrorInternalError)
			return
		}
	}

	myNewChannelDescriptor := &ChannelDescriptor{
		AppID:               request.AppID,
		StatefulReader:      statefulReader,
		EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
	}

	d.newChannelMapLock.Lock()
	d.newChannelMap[channelID] = myNewChannelDescriptor
	d.newChannelMapLock.Unlock()

	// send reply back to client
	conn.sendResponse(&Response{
		AppID: request.AppID,
		ResumeReadChannelReply: &thin.ResumeReadChannelReply{
			QueryID:   request.ResumeReadChannel.QueryID,
			ChannelID: channelID,
			ErrorCode: thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) sendResumeReadChannelQueryError(request *Request, errorCode uint8) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf("no connection associated with AppID %x", request.AppID[:])
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		ResumeReadChannelQueryReply: &thin.ResumeReadChannelQueryReply{
			QueryID:   request.ResumeReadChannelQuery.QueryID,
			ErrorCode: errorCode,
		},
	})
}

func (d *Daemon) resumeReadChannelQuery(request *Request) {
	// NOTE(David):
	// handle the request in several steps:
	// 1. validate request
	// 2. set used read cap map entry
	// 3. create new channel descriptor
	// 4. inspect optional request fields that are only used for resumption of a previously prepared read query blob

	err := d.validateResumeReadChannelQueryRequest(request)
	if err != nil {
		d.log.Errorf("BUG, invalid request: %v", err)
		d.sendResumeReadChannelQueryError(request, thin.ThinClientErrorInvalidResumeReadChannelRequest)
		return
	}

	//readCapBlob, err := request.ResumeReadChannelQuery.ReadCap.MarshalBinary()
	//readCapHash := hash.Sum256(readCapBlob)

	//d.capabilityLock.Lock()
	//_, ok := d.usedReadCaps[readCapHash]
	//if ok {
	//	d.log.Errorf("BUG, read cap already in use")
	//	d.sendResumeReadChannelQueryError(request, thin.ThinClientCapabilityAlreadyInUse)
	//	d.capabilityLock.Unlock()
	//	return
	//}
	//d.usedReadCaps[readCapHash] = true
	//d.capabilityLock.Unlock()

	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf("no connection associated with AppID %x", request.AppID[:])
		d.sendResumeReadChannelQueryError(request, thin.ThinClientErrorConnectionLost)
		return
	}
	channelID := d.generateUniqueChannelID()
	var statefulReader *bacap.StatefulReader
	statefulReader, err = bacap.NewStatefulReaderWithIndex(
		request.ResumeReadChannelQuery.ReadCap,
		constants.PIGEONHOLE_CTX,
		request.ResumeReadChannelQuery.NextMessageIndex)
	if err != nil {
		d.log.Errorf("BUG, failed to create stateful reader: %v", err)
		d.sendResumeReadChannelQueryError(request, thin.ThinClientErrorInternalError)
		return
	}

	myNewChannelDescriptor := &ChannelDescriptor{
		AppID:               request.AppID,
		StatefulReader:      statefulReader,
		EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
	}

	// store envelope descriptor for later use
	envelopeDesc, err := EnvelopeDescriptorFromBytes(request.ResumeReadChannelQuery.EnvelopeDescriptor)
	if err != nil {
		d.log.Errorf("resumeReadChannelQuery: Failed to parse envelope descriptor: %v", err)
		d.sendResumeReadChannelQueryError(request, thin.ThinClientErrorInvalidRequest)
		return
	}
	envHash := request.ResumeReadChannelQuery.EnvelopeHash
	myNewChannelDescriptor.EnvelopeDescriptors[*envHash] = envelopeDesc

	d.newChannelMapLock.Lock()
	d.newChannelMap[channelID] = myNewChannelDescriptor
	d.newChannelMapLock.Unlock()

	// send reply back to client
	conn.sendResponse(&Response{
		AppID: request.AppID,
		ResumeReadChannelQueryReply: &thin.ResumeReadChannelQueryReply{
			QueryID:   request.ResumeReadChannelQuery.QueryID,
			ChannelID: channelID,
			ErrorCode: thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) sendResumeReadChannelError(request *Request, errorCode uint8) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf("no connection associated with AppID %x", request.AppID[:])
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		ResumeReadChannelReply: &thin.ResumeReadChannelReply{
			QueryID:   request.ResumeReadChannel.QueryID,
			ErrorCode: errorCode,
		},
	})
}

// handleChannelReply tries to handle the reply and if successful it sends a
// response to the appropriate thin client connection. Otherwise it returns an error.
func (d *Daemon) handleChannelReply(appid *[AppIDLength]byte,
	mesgID *[MessageIDLength]byte,
	surbid *[sphinxConstants.SURBIDLength]byte,
	payload []byte) error {

	// First, parse the courier query reply to check what type of reply it is
	courierQueryReply, err := pigeonhole.ParseCourierQueryReply(payload)
	if err != nil {
		return fmt.Errorf("BUG, failed to unmarshal courier query reply: %s", err)
	}

	// Handle envelope replies (read/write operations)
	switch {
	case courierQueryReply.ReplyType == 0:
		return d.handleCourierEnvelopeReply(appid, mesgID, surbid, courierQueryReply.EnvelopeReply)
	case courierQueryReply.ReplyType == 1:
		return fmt.Errorf("BUG, copy command replies are not supported in the new API yet")
	}

	// not reached
	return nil
}

func mapCourierErrorToThinClientError(courierErrorCode uint8) uint8 {
	switch courierErrorCode {
	case pigeonhole.EnvelopeErrorSuccess:
		return thin.ThinClientSuccess
	case pigeonhole.EnvelopeErrorInvalidEnvelope:
		return thin.ThinClientErrorInvalidRequest
	case pigeonhole.EnvelopeErrorCacheCorruption:
		return thin.ThinClientErrorCourierCacheCorruption
	case pigeonhole.EnvelopeErrorPropagationError:
		return thin.ThinClientPropagationError
	default:
		return thin.ThinClientErrorInternalError
	}
}

func (d *Daemon) handleCourierEnvelopeReply(appid *[AppIDLength]byte,
	mesgID *[MessageIDLength]byte,
	surbid *[sphinxConstants.SURBIDLength]byte,
	courierEnvelopeReply *pigeonhole.CourierEnvelopeReply) error {

	channelID, channelDesc, err := d.lookupNewChannel(surbid)
	if err != nil {
		// NOTE(David): we could possibly send a reply to the thin client indicating this bug/error
		// but instead we're going to rely on the logging. Either way it's not recoverable.
		return fmt.Errorf("BUG, SURB ID not found: %v", err)
	}

	conn := d.listener.getConnection(appid)
	if conn == nil {
		return fmt.Errorf("BUG, no connection associated with AppID %x", appid[:])
	}

	isReader, isWriter, err := d.validateNewChannel(channelID, channelDesc)
	if err != nil {
		return fmt.Errorf("BUG, invalid channel: %v", err)
	}

	if courierEnvelopeReply == nil {
		return fmt.Errorf("BUG, courier envelope reply is nil")
	}

	d.log.Debugf("DEBUG: Processing courier envelope reply - ReplyType=%d, ErrorCode=%d, PayloadLen=%d, isWriter=%v, isReader=%v",
		courierEnvelopeReply.ReplyType, courierEnvelopeReply.ErrorCode, courierEnvelopeReply.PayloadLen, isWriter, isReader)

	switch {
	case courierEnvelopeReply.ErrorCode != 0:
		// send error response to client
		// mapCourierErrorToThinClientError(courierEnvelopeReply.ErrorCode)
		return conn.sendResponse(&Response{
			AppID: appid,
			ChannelQueryReplyEvent: &thin.ChannelQueryReplyEvent{
				MessageID: mesgID,
				Payload:   []byte{},
				ErrorCode: mapCourierErrorToThinClientError(courierEnvelopeReply.ErrorCode),
			},
		})
	case courierEnvelopeReply.ReplyType == pigeonhole.ReplyTypeACK:
		d.log.Debugf("DEBUG: Received ACK reply for channel %d, isWriter=%v", channelID, isWriter)
		// ACK indicates successful write operation - advance StatefulWriter state
		if false { // if isWriter {
			// TODO: the application can (and will) resend the same message several times to the courier,
			// each of them warranting an ACK, which will cause the stream to skip messages.
			// For now, clients should use the ResumeWriteChannel API to set the index.
			// is this what we want?
			channelDesc.StatefulWriterLock.Lock()
			d.log.Debugf("DEBUG: Advancing StatefulWriter state for channel %d", channelID)
			err := channelDesc.StatefulWriter.AdvanceState()
			channelDesc.StatefulWriterLock.Unlock()
			if err != nil {
				d.log.Errorf("Failed to advance StatefulWriter state for channel %d: %s", channelID, err)
				// Continue to send response even if state advancement fails
			} else {
				d.log.Debugf("DEBUG: Successfully advanced StatefulWriter state for channel %d", channelID)
			}
		}

		// send empty response to client
		return conn.sendResponse(&Response{
			AppID: appid,
			ChannelQueryReplyEvent: &thin.ChannelQueryReplyEvent{
				MessageID: mesgID,
				Payload:   []byte{},
				ErrorCode: thin.ThinClientSuccess,
			},
		})
	case courierEnvelopeReply.Payload == nil || courierEnvelopeReply.PayloadLen == 0:
		// send empty response to client (for non-ACK empty replies)
		return conn.sendResponse(&Response{
			AppID: appid,
			ChannelQueryReplyEvent: &thin.ChannelQueryReplyEvent{
				MessageID: mesgID,
				Payload:   []byte{},
				ErrorCode: thin.ThinClientSuccess,
			},
		})
	case courierEnvelopeReply.ReplyType == pigeonhole.ReplyTypePayload:

		env, envelopeDesc, privateKey, err := d.processEnvelopeReply(courierEnvelopeReply, channelDesc)
		if err != nil {
			d.log.Errorf("NEW API REPLY: Failed to process envelope reply: %s", err)
			return err
		}

		d.log.Infof("NEW API REPLY: Decrypting MKEM Envelope env:%v envelopeDesc:%v", env, envelopeDesc)

		innerMsg, err := d.decryptMKEMEnvelope(env, envelopeDesc, privateKey)
		if err != nil {
			d.log.Errorf("NEW API REPLY: Failed to decrypt MKEM envelope: %s", err)
			return err
		}

		envHash := (*[hash.HashSize]byte)(env.EnvelopeHash[:])

		d.log.Errorf("channellID %d messageid:%v envHash:%v isReader:%v isWriter:%v innerMsg:%v", channelID, mesgID, envHash, isReader, isWriter, innerMsg)
		// from here on here, these two switch cases are the success cases:
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
				ReplyIndex:  courierEnvelopeReply.ReplyIndex,
			}
			return d.handleNewReadReply(params, innerMsg.ReadReply)
		case innerMsg.WriteReply != nil:
			params := &ReplyHandlerParams{
				AppID:       appid,
				MessageID:   mesgID,
				ChannelID:   channelID,
				ChannelDesc: channelDesc,
				EnvHash:     envHash,
				IsReader:    isReader,
				IsWriter:    isWriter,
				ReplyIndex:  courierEnvelopeReply.ReplyIndex,
			}
			return d.handleNewWriteReply(params, innerMsg.WriteReply)
		}

		// if we got this far something failed
		d.log.Errorf("bug 6, invalid book keeping for channelID %d", channelID)

		// send error code back to client
		return conn.sendResponse(&Response{
			AppID: appid,
			ChannelQueryReplyEvent: &thin.ChannelQueryReplyEvent{
				MessageID: mesgID,
				Payload:   []byte{},
				ErrorCode: thin.ThinClientErrorInvalidChannel,
			},
		})
	}

	// not reached
	return nil
}

// lookupNewChannel finds the channel descriptor for a given SURB ID (new API)
func (d *Daemon) lookupNewChannel(surbid *[sphinxConstants.SURBIDLength]byte) (uint16, *ChannelDescriptor, error) {
	d.newSurbIDToChannelMapLock.RLock()
	channelID, ok := d.newSurbIDToChannelMap[*surbid]
	d.newSurbIDToChannelMapLock.RUnlock()
	if !ok {
		d.log.Errorf("BUG no channelID found for surbID %x in new API", surbid[:])
		return 0, nil, fmt.Errorf("no channelID found for surbID %x in new API", surbid[:])
	}

	d.newChannelMapLock.RLock()
	channelDesc, ok := d.newChannelMap[channelID]
	d.newChannelMapLock.RUnlock()
	if !ok || channelDesc == nil {
		d.log.Errorf("BUG no channel found for channelID %d in new API", channelID)
		return 0, nil, fmt.Errorf("no channel found for channelID %d in new API", channelID)
	}

	return channelID, channelDesc, nil
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
			d.log.Errorf("MKEM DECRYPT: no replicaNum:%v in doc:%v", replicaNum, doc)
			continue
		}

		replicaPubKeyBytes, ok := desc.EnvelopeKeys[replicaEpoch]
		if !ok || len(replicaPubKeyBytes) == 0 {
			d.log.Errorf("MKEM DECRYPT: no usable replicaPubKeyBytes in replicaEpoch:%v", replicaEpoch)
			continue
		}

		replicaPubKey, err := replicaCommon.NikeScheme.UnmarshalBinaryPublicKey(replicaPubKeyBytes)
		if err != nil {
			d.log.Errorf("MKEM DECRYPT: can't parse replicaPubKey: %v", err)
			continue
		}

		// Try to decrypt with this replica's public key
		rawInnerMsg, err = replicaCommon.MKEMNikeScheme.DecryptEnvelope(privateKey, replicaPubKey, env.Payload)
		if err == nil {
			d.log.Errorf("MKEM DECRYPT: no rawInnerMsg for replicaNum:%v: %v", replicaNum, err)
			break
		}
	}

	if rawInnerMsg == nil {
		d.log.Errorf("MKEM DECRYPT FAILED with all possible replicas")
		return nil, fmt.Errorf("failed to decrypt envelope with any replica key")
	}
	innerMsg, err := pigeonhole.ParseReplicaMessageReplyInnerMessage(rawInnerMsg)
	if err != nil {
		d.log.Errorf("failed to unmarshal inner message: %s %v", err, rawInnerMsg)
		return nil, fmt.Errorf("failed to unmarshal inner message: %s", err)
	}

	return innerMsg, nil
}

func (d *Daemon) validateSendChannelQueryRequest(request *Request) error {
	if request.SendChannelQuery.MessageID == nil {
		return fmt.Errorf("MessageID cannot be nil")
	}
	if request.SendChannelQuery.ChannelID == nil {
		return fmt.Errorf("ChannelID cannot be nil")
	}
	if request.SendChannelQuery.DestinationIdHash == nil {
		return fmt.Errorf("DestinationIdHash cannot be nil")
	}
	if request.SendChannelQuery.RecipientQueueID == nil {
		return fmt.Errorf("RecipientQueueID cannot be nil")
	}
	if request.SendChannelQuery.Payload == nil {
		return fmt.Errorf("Payload cannot be nil")
	}
	return nil
}

func (d *Daemon) sendChannelQuery(request *Request) {
	err := d.validateSendChannelQueryRequest(request)
	if err != nil {
		d.log.Errorf("BUG, invalid request: %v", err)
		d.sendErrorResponse(request, thin.ThinClientErrorInvalidRequest, "SendChannelQuery")
		return
	}

	var surbKey []byte
	var rtt time.Duration
	var now time.Time

	surbID := common.NewSURBID()
	surbKey, rtt, err = d.client.SendChannelQuery(request.SendChannelQuery, surbID)
	if err != nil {
		d.log.Debugf("SendCiphertext error: %s", err.Error())
	}

	now = time.Now()
	fetchInterval := d.client.GetPollInterval()
	slop := time.Second
	duration := rtt + fetchInterval + slop
	replyArrivalTime := now.Add(duration)

	d.timerQueue.Push(uint64(replyArrivalTime.UnixNano()), surbID)

	incomingConn := d.listener.getConnection(request.AppID)
	if incomingConn == nil {
		d.log.Errorf("no connection associated with AppID %x", request.AppID[:])
		return
	}

	response := &Response{
		AppID: request.AppID,
		ChannelQuerySentEvent: &thin.ChannelQuerySentEvent{
			MessageID: request.SendChannelQuery.MessageID,
			SentAt:    now,
			ReplyETA:  rtt,
			ErrorCode: thin.ThinClientSuccess,
		},
	}
	err = incomingConn.sendResponse(response)
	if err != nil {
		d.log.Errorf("failed to send Response: %s", err)
	}

	d.channelRepliesLock.Lock()
	d.channelReplies[*surbID] = replyDescriptor{
		ID:      request.SendChannelQuery.MessageID,
		appID:   request.AppID,
		surbKey: surbKey,
	}
	d.channelRepliesLock.Unlock()

	d.newSurbIDToChannelMapLock.Lock()
	d.newSurbIDToChannelMap[*surbID] = *request.SendChannelQuery.ChannelID
	d.newSurbIDToChannelMapLock.Unlock()
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
		d.log.Debugf("SendCiphertext error: %s", err.Error())
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
				var errStr string
				if err != nil {
					errStr = err.Error()
				}
				response := &Response{
					AppID: request.AppID,
					MessageSentEvent: &thin.MessageSentEvent{
						MessageID: messageID,
						SURBID:    surbID,
						SentAt:    now,
						ReplyETA:  rtt,
						Err:       errStr,
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
		// Old API: store in regular replies
		d.replies[*request.SendMessage.SURBID] = replyDescriptor{
			ID:      request.SendMessage.ID,
			appID:   request.AppID,
			surbKey: surbKey,
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
				Payload:   []byte{},
				SURBID:    surbID,
				ErrorCode: thin.ThinClientErrorMaxRetries,
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

// validateReadReplySignature checks if the signature is valid (not all zeros)
func (d *Daemon) validateReadReplySignature(signature [64]uint8) error {
	var zeroSig [64]uint8
	if signature == zeroSig {
		d.log.Debugf("replica returned zero signature for read operation")
		return fmt.Errorf("replica read reply has zero signature")
	}
	return nil
}

// decryptReadReplyPayload handles the decryption and extraction of the payload
func (d *Daemon) decryptReadReplyPayload(params *ReplyHandlerParams, readReply *pigeonhole.ReplicaReadReply) ([]byte, error) {
	params.ChannelDesc.StatefulReaderLock.Lock()
	defer params.ChannelDesc.StatefulReaderLock.Unlock()

	boxid, err := params.ChannelDesc.StatefulReader.NextBoxID()
	if err != nil {
		d.log.Errorf("Failed to get next box ID for channel %d: %s", params.ChannelID, err)
		return nil, fmt.Errorf("failed to get next box ID: %s", err)
	}
	saved := params.ChannelDesc.StatefulReader.NextIndex

	// BACAP decrypt the payload
	signature := (*[bacap.SignatureSize]byte)(readReply.Signature[:])
	innerplaintext, err := params.ChannelDesc.StatefulReader.DecryptNext(
		[]byte(constants.PIGEONHOLE_CTX),
		*boxid,
		readReply.Payload,
		*signature)

	if err != nil {
		d.log.Errorf("BACAP DECRYPT FAILED for BoxID %x: %s", boxid[:], err)
		return nil, fmt.Errorf("failed to decrypt next: %s", err)
	} else {
		//if params.ReadChannel.MessageBoxIndex != nil {
		params.ChannelDesc.StatefulReader.NextIndex = saved // restore it because DecryptNext advanced it
		d.log.Errorf("BACAP state NOTNOT advanced for channel %d BoxID %x", params.ChannelID, boxid[:])
		// } else {
		// 	      d.log.Errorf("BACAP state advanced for channel %d BoxID %x", params.ChannelID, boxid[:])
		//  }
	}

	// Extract the original message from the padded payload
	originalMessage, err := pigeonhole.ExtractMessageFromPaddedPayload(innerplaintext)
	if err != nil {
		d.log.Errorf("Failed to extract message from padded payload: %s", err)
		return nil, fmt.Errorf("failed to extract message from padded payload: %s", err)
	}

	return originalMessage, nil
}

// processReadReplyPayload processes the read reply and returns payload and error
func (d *Daemon) processReadReplyPayload(params *ReplyHandlerParams, readReply *pigeonhole.ReplicaReadReply) ([]byte, error) {
	if readReply.ErrorCode != 0 {
		d.log.Errorf("read failed for channel %d with error code %d (ReplicaErrorNotFound = 1)", params.ChannelID, readReply.ErrorCode)
		return nil, fmt.Errorf("read failed with error code %d", readReply.ErrorCode)
	}

	if err := d.validateReadReplySignature(readReply.Signature); err != nil {
		return nil, err
	}

	return d.decryptReadReplyPayload(params, readReply)
}

// handleNewReadReply processes a read reply (new API)
func (d *Daemon) handleNewReadReply(params *ReplyHandlerParams, readReply *pigeonhole.ReplicaReadReply) error {
	if !params.IsReader {
		d.log.Errorf("bug 4, invalid book keeping for channelID %d", params.ChannelID)
		return fmt.Errorf("bug 4, invalid book keeping for channelID %d", params.ChannelID)
	}

	conn := d.listener.getConnection(params.AppID)
	if conn == nil {
		return fmt.Errorf("BUG, no connection associated with AppID %x", params.AppID[:])
	}

	var errorCode uint8 = thin.ThinClientSuccess
	var payload []byte
	var err error
	if readReply.ErrorCode == 1 {
		// this is "box not found"
		payload = []byte{}
	} else {
		if readReply.ErrorCode == 0 {
			payload, err = d.processReadReplyPayload(params, readReply)
			if err != nil {
				d.log.Errorf("chan %v failed to process read reply payload: %s", params.ChannelID, err)
				payload = []byte{} // Ensure empty payload on error
				errorCode = thin.ThinClientErrorInvalidPayload
			}
		} else {
			payload = []byte{}
			errorCode = thin.ThinClientErrorInternalError // TODO this is a lie, it's a replica error.
		}
	}

	if readReply.ErrorCode == 0 {
		// deliver the read result to thin client if we can decrypt it
		err = conn.sendResponse(&Response{
			AppID: params.AppID,
			MessageReplyEvent: &thin.MessageReplyEvent{
				MessageID:  params.MessageID,
				Payload:    payload,
				ReplyIndex: &params.ReplyIndex,
				ErrorCode:  errorCode,
			},
		})
		if err != nil {
			return fmt.Errorf("chan %d: failed to send MessageReplyEvent to client: %s", params.ChannelID, err)
		}
	}

	// deliver the read result to thin client
	err = conn.sendResponse(&Response{
		AppID: params.AppID,
		ChannelQueryReplyEvent: &thin.ChannelQueryReplyEvent{
			MessageID:  params.MessageID,
			Payload:    payload,
			ReplyIndex: &params.ReplyIndex,
			ErrorCode:  errorCode,
		},
	})
	if err != nil {
		return fmt.Errorf("chan %d: failed to send read response to client: %s", params.ChannelID, err)
	}

	return nil
}

func (d *Daemon) handleNewWriteReply(params *ReplyHandlerParams, writeReply *pigeonhole.ReplicaWriteReply) error {
	if !params.IsWriter {
		d.log.Errorf("bug 5, invalid book keeping for channelID %d", params.ChannelID)
		return fmt.Errorf("bug 5, invalid book keeping for channelID %d", params.ChannelID)
	}

	conn := d.listener.getConnection(params.AppID)
	if conn == nil {
		return fmt.Errorf("BUG, no connection associated with AppID %x", params.AppID[:])
	}

	// Note: StatefulWriter state is advanced in handleCourierEnvelopeReply when ACK is received

	// deliver the write result to thin client
	err := conn.sendResponse(&Response{
		AppID: params.AppID,
		ChannelQueryReplyEvent: &thin.ChannelQueryReplyEvent{
			MessageID:  params.MessageID,
			Payload:    []byte{}, // Empty payload for write operations
			ReplyIndex: &params.ReplyIndex,
			ErrorCode:  writeReply.ErrorCode,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to send write response to client: %s", err)
	}

	return nil
}
