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

	// Channel reply tracking (used by both old and new API)
	channelReplies     map[[sphinxConstants.SURBIDLength]byte]replyDescriptor
	channelRepliesLock *sync.RWMutex

	// Channel management (new API)
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
		// Channel reply tracking
		channelReplies:     make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		channelRepliesLock: new(sync.RWMutex),
		// Channel management (new API)
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

			case request.CreateWriteChannel != nil:
				d.createWriteChannel(request)
			case request.CreateReadChannel != nil:
				d.createReadChannel(request)
			case request.WriteChannel != nil:
				d.writeChannel(request)
			case request.ReadChannel != nil:
				d.readChannel(request)
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
		d.log.Debugf("SURB reply decryption error: %s", err.Error())
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
			d.channelRepliesLock.Lock()
			delete(d.channelReplies, *reply.surbID)
			d.channelRepliesLock.Unlock()

			// Clean up from new API maps
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
				Err:       "", // No error
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

	// Use new API only
	newChannelID, newChannelDesc, newErr := d.lookupNewChannel(surbid)
	if newErr != nil {
		d.log.Errorf("SURB ID %x not found in new API maps", surbid[:8])
		return fmt.Errorf("SURB ID not found: %v", newErr)
	}
	return d.handleNewChannelReply(appid, mesgID, surbid, plaintext, conn, newChannelID, newChannelDesc)
}

// handleNewChannelReply handles channel replies for the new API
func (d *Daemon) handleNewChannelReply(appid *[AppIDLength]byte,
	mesgID *[MessageIDLength]byte,
	surbid *[sphinxConstants.SURBIDLength]byte,
	plaintext []byte,
	conn *incomingConn,
	channelID uint16,
	channelDesc *ChannelDescriptor) error {

	if len(plaintext) == 0 {
		return nil
	}

	isReader, isWriter, err := d.validateNewChannel(channelID, channelDesc)
	if err != nil {
		return err
	}

	// First, parse the courier query reply to check what type of reply it is
	courierQueryReply, err := pigeonhole.ParseCourierQueryReply(plaintext)
	if err != nil {
		d.log.Errorf("NEW API REPLY: Failed to unmarshal courier query reply: %s", err)
		return fmt.Errorf("failed to unmarshal courier query reply: %s", err)
	}

	// Copy command replies are not supported in the new API

	// Handle envelope replies (read/write operations)
	if courierQueryReply.EnvelopeReply != nil {
		// Check if the envelope reply has an empty payload (no data available yet)
		if len(courierQueryReply.EnvelopeReply.Payload) == 0 {
			// Send empty response to client so they can retry
			err := conn.sendResponse(&Response{
				AppID: appid,
				MessageReplyEvent: &thin.MessageReplyEvent{
					MessageID: mesgID,
					Payload:   nil, // Empty payload
					Err:       "",  // No error - just no data yet
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
				ReplyIndex:  courierQueryReply.EnvelopeReply.ReplyIndex,
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
				ReplyIndex:  courierQueryReply.EnvelopeReply.ReplyIndex,
			}
			return d.handleNewWriteReply(params, innerMsg.WriteReply)
		}
		d.log.Errorf("bug 6, invalid book keeping for channelID %d", channelID)
		return fmt.Errorf("bug 6, invalid book keeping for channelID %d", channelID)
	}

	d.log.Errorf("courier query reply contains neither envelope reply nor copy command reply")
	return fmt.Errorf("courier query reply contains neither envelope reply nor copy command reply")
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
	if !ok {
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
			continue
		}

		replicaPubKeyBytes, ok := desc.EnvelopeKeys[replicaEpoch]
		if !ok || len(replicaPubKeyBytes) == 0 {
			continue
		}

		replicaPubKey, err := replicaCommon.NikeScheme.UnmarshalBinaryPublicKey(replicaPubKeyBytes)
		if err != nil {
			continue
		}

		// Try to decrypt with this replica's public key
		rawInnerMsg, err = replicaCommon.MKEMNikeScheme.DecryptEnvelope(privateKey, replicaPubKey, env.Payload)
		if err == nil {
			break
		}
	}

	if rawInnerMsg == nil {
		d.log.Errorf("MKEM DECRYPT FAILED with all possible replicas")
		return nil, fmt.Errorf("failed to decrypt envelope with any replica key")
	}
	innerMsg, err := pigeonhole.ParseReplicaMessageReplyInnerMessage(rawInnerMsg)
	if err != nil {
		d.log.Errorf("failed to unmarshal inner message: %s", err)
		return nil, fmt.Errorf("failed to unmarshal inner message: %s", err)
	}

	return innerMsg, nil
}

// NewReplyHandlerParams groups parameters for reply handler functions
type NewReplyHandlerParams struct {
	AppID       *[AppIDLength]byte
	MessageID   *[MessageIDLength]byte
	ChannelID   uint16
	ChannelDesc *ChannelDescriptor
	EnvHash     *[hash.HashSize]byte
	IsReader    bool
	IsWriter    bool
	Conn        *incomingConn
	ReplyIndex  uint8
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
		// Check if this is a new API channel query (has ChannelID field)
		if request.SendMessage.ChannelID != nil {

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
				Err:       "max retries met",
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
func (d *Daemon) decryptReadReplyPayload(params *NewReplyHandlerParams, readReply *pigeonhole.ReplicaReadReply) ([]byte, error) {
	params.ChannelDesc.StatefulReaderLock.Lock()
	defer params.ChannelDesc.StatefulReaderLock.Unlock()

	boxid, err := params.ChannelDesc.StatefulReader.NextBoxID()
	if err != nil {
		d.log.Errorf("Failed to get next box ID for channel %d: %s", params.ChannelID, err)
		return nil, fmt.Errorf("failed to get next box ID: %s", err)
	}

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
func (d *Daemon) processReadReplyPayload(params *NewReplyHandlerParams, readReply *pigeonhole.ReplicaReadReply) ([]byte, error) {
	if readReply.ErrorCode != 0 {
		d.log.Errorf("read failed for channel %d with error code %d", params.ChannelID, readReply.ErrorCode)
		return nil, fmt.Errorf("read failed with error code %d", readReply.ErrorCode)
	}

	if err := d.validateReadReplySignature(readReply.Signature); err != nil {
		return nil, err
	}

	return d.decryptReadReplyPayload(params, readReply)
}

// handleNewReadReply processes a read reply (new API)
func (d *Daemon) handleNewReadReply(params *NewReplyHandlerParams, readReply *pigeonhole.ReplicaReadReply) error {
	if !params.IsReader {
		d.log.Errorf("bug 4, invalid book keeping for channelID %d", params.ChannelID)
		return fmt.Errorf("bug 4, invalid book keeping for channelID %d", params.ChannelID)
	}

	payload, replyErr := d.processReadReplyPayload(params, readReply)

	// For new API, use MessageReplyEvent to deliver the read result
	var errStr string
	if replyErr != nil {
		errStr = replyErr.Error()
	}
	err := params.Conn.sendResponse(&Response{
		AppID: params.AppID,
		MessageReplyEvent: &thin.MessageReplyEvent{
			MessageID:  params.MessageID,
			Payload:    payload,
			ReplyIndex: &params.ReplyIndex,
			Err:        errStr,
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
	var errStr string
	if replyErr != nil {
		errStr = replyErr.Error()
	}
	err := params.Conn.sendResponse(&Response{
		AppID: params.AppID,
		MessageReplyEvent: &thin.MessageReplyEvent{
			MessageID: params.MessageID,
			Err:       errStr,
		},
	})
	if err != nil {
		d.log.Errorf("Failed to send write response to client: %s", err)
		return fmt.Errorf("failed to send write response to client: %s", err)
	}

	return nil
}
