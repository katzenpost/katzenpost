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

	// Capability deduplication maps to prevent reusing read/write capabilities
	usedReadCaps   map[string]bool // Maps binary representation of UniversalReadCap to true
	usedWriteCaps  map[string]bool // Maps binary representation of BoxOwnerCap to true
	capabilityLock *sync.RWMutex   // Protects both capability maps

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
		// capability deduplication fields:
		usedReadCaps:   make(map[string]bool),
		usedWriteCaps:  make(map[string]bool),
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
			case request.CreateWriteChannel != nil:
				d.createWriteChannel(request)
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
			d.channelRepliesLock.Lock()
			delete(d.channelReplies, *reply.surbID)
			d.channelRepliesLock.Unlock()

			d.surbIDToChannelMapLock.Lock()
			delete(d.surbIDToChannelMap, *reply.surbID)
			d.surbIDToChannelMapLock.Unlock()
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

	channelID, channelDesc, err := d.lookupChannel(surbid)
	if err != nil {
		return err
	}

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
				SURBID:      surbid,
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
				SURBID:      surbid,
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

// lookupChannel finds the channel descriptor for a given SURB ID
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
	channelDesc.EnvelopeLock.RLock()
	mapSize := len(channelDesc.EnvelopeDescriptors)
	envelopeDesc, ok := channelDesc.EnvelopeDescriptors[*envHash]
	channelDesc.EnvelopeLock.RUnlock()

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

// ReplyHandlerParams groups parameters for reply handler functions
type ReplyHandlerParams struct {
	AppID       *[AppIDLength]byte
	MessageID   *[MessageIDLength]byte
	SURBID      *[sphinxConstants.SURBIDLength]byte
	ChannelID   [thin.ChannelIDLength]byte
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
	params.ChannelDesc.ReaderLock.Lock()
	signature := (*[bacap.SignatureSize]byte)(readReply.Signature[:])
	innerplaintext, err := params.ChannelDesc.StatefulReader.DecryptNext(
		[]byte(constants.PIGEONHOLE_CTX),
		*boxid,
		readReply.Payload,
		*signature)
	params.ChannelDesc.ReaderLock.Unlock()
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

	// For the new API, we need to send a MessageReplyEvent with the actual message content
	// since ReadChannelReply now only contains the prepared query payload
	err = params.Conn.sendResponse(&Response{
		AppID: params.AppID,
		MessageReplyEvent: &thin.MessageReplyEvent{
			MessageID: params.MessageID,
			SURBID:    params.SURBID,
			Payload:   originalMessage,
		},
	})
	if err != nil {
		d.log.Errorf("Failed to send response to client: %s", err)
		// Don't clean up envelope descriptors if response sending failed - allow retry
		return fmt.Errorf("failed to send response to client: %s", err)
	}

	params.ChannelDesc.EnvelopeLock.Lock()
	delete(params.ChannelDesc.EnvelopeDescriptors, *params.EnvHash)
	params.ChannelDesc.EnvelopeLock.Unlock()

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
	if copyReply.ErrorCode != 0 {
		d.log.Errorf("copy command failed for channel %x with error code %d", channelID[:], copyReply.ErrorCode)
	} else {
		d.log.Debugf("copy command completed successfully for channel %x", channelID[:])
	}

	var errorCode uint8 = thin.ThinClientErrorSuccess
	if copyReply.ErrorCode != 0 {
		errorCode = thin.ThinClientErrorInternalError
	}
	err := conn.sendResponse(&Response{
		AppID: appid,
		CopyChannelReply: &thin.CopyChannelReply{
			ChannelID: channelID,
			ErrorCode: errorCode,
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

	// Only advance state if the write was successful
	if writeReply.ErrorCode == 0 {
		// Advance StatefulWriter state now that courier has confirmed successful storage
		params.ChannelDesc.WriterLock.Lock()
		if params.ChannelDesc.StatefulWriter != nil {
			nextIndex, err := params.ChannelDesc.StatefulWriter.NextIndex.NextIndex()
			if err != nil {
				params.ChannelDesc.WriterLock.Unlock()
				d.log.Errorf("Failed to advance writer state: %s", err)
				return fmt.Errorf("failed to advance writer state: %s", err)
			}
			params.ChannelDesc.StatefulWriter.LastOutboxIdx = params.ChannelDesc.StatefulWriter.NextIndex
			params.ChannelDesc.StatefulWriter.NextIndex = nextIndex
			d.log.Debugf("Advanced writer state for channel %x", params.ChannelID[:])
		}
		params.ChannelDesc.WriterLock.Unlock()
	} else {
		d.log.Errorf("failed to write to channel, error code: %d", writeReply.ErrorCode)
		// Don't advance state on write failure - allow retry with same index
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

	params.ChannelDesc.EnvelopeLock.Lock()
	delete(params.ChannelDesc.EnvelopeDescriptors, *params.EnvHash)
	params.ChannelDesc.EnvelopeLock.Unlock()

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
				var errorCode uint8 = thin.ThinClientErrorSuccess
				if err != nil {
					errorCode = thin.ThinClientErrorInternalError
				}
				response := &Response{
					AppID: request.AppID,
					MessageSentEvent: &thin.MessageSentEvent{
						MessageID: messageID,
						SURBID:    surbID,
						SentAt:    now,
						ReplyETA:  rtt,
						ErrorCode: errorCode,
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
		d.replies[*request.SendMessage.SURBID] = replyDescriptor{
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
				ErrorCode: thin.ThinClientErrorMaxRetries,
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
	if channelDesc.StatefulWriter == nil || channelDesc.BoxOwnerCap == nil {
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

	// Extract the WriteCap from the BoxOwnerCap
	writeCap := channelDesc.BoxOwnerCap

	// Create the CopyCommand
	writeCapBytes, err := writeCap.MarshalBinary()
	if err != nil {
		d.log.Errorf("failed to marshal BoxOwnerCap: %s", err)
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
	destinationIdHash, recipientQueueID := pigeonhole.GetRandomCourier(doc)

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
				ErrorCode: thin.ThinClientErrorInternalError,
			},
		})
	}
}
