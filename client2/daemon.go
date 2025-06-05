// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"crypto/hmac"
	"errors"
	"fmt"
	mrand "math/rand"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client2/common"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/constants"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/worker"
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
			case request.IsLoopDecoy:
				d.sendLoopDecoy(request)
			case request.IsDropDecoy:
				d.sendDropDecoy()
			case request.IsSendOp:
				d.send(request)
			case request.IsARQSendOp:
				d.send(request)

				// New Pigeonhole Channel related commands proceed here:

			case request.CreateChannel != nil:
				d.createChannel(request)
			case request.CreateReadChannel != nil:
				d.createReadChannel(request)
			case request.WriteChannel != nil:
				d.writeChannel(request)
			case request.ReadChannel != nil:
				d.readChannel(request)
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
				d.channelRepliesLock.Lock()
				delete(d.channelReplies, *surbID)
				d.channelRepliesLock.Unlock()

				d.surbIDToChannelMapLock.Lock()
				delete(d.surbIDToChannelMap, *surbID)
				d.surbIDToChannelMapLock.Unlock()
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
		d.handleChannelReply(desc.appID, desc.ID, reply.surbID, plaintext, conn)
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

	d.surbIDToChannelMapLock.RLock()
	channelID, ok := d.surbIDToChannelMap[*surbid]
	d.surbIDToChannelMapLock.RUnlock()
	if !ok {
		d.log.Errorf("no channelID found for surbID %x", surbid[:])
		return fmt.Errorf("no channelID found for surbID %x", surbid[:])
	}

	d.channelMapLock.RLock()
	channelDesc, ok := d.channelMap[channelID]
	d.channelMapLock.RUnlock()
	if !ok {
		d.log.Errorf("no channel found for channelID %x", channelID[:])
		return fmt.Errorf("no channel found for channelID %x", channelID[:])
	}

	// sanity check
	if channelDesc.StatefulReader == nil && channelDesc.StatefulWriter == nil {
		d.log.Errorf("bug 1, invalid book keeping for channelID %x", channelID[:])
		return fmt.Errorf("bug 1, invalid book keeping for channelID %x", channelID[:])
	}
	if channelDesc.StatefulReader != nil && channelDesc.StatefulWriter != nil {
		d.log.Errorf("bug 2, invalid book keeping for channelID %x", channelID[:])
		return fmt.Errorf("bug 2, invalid book keeping for channelID %x", channelID[:])
	}
	if channelDesc.EnvelopeDescriptors == nil {
		d.log.Errorf("bug 3, invalid book keeping for channelID %x", channelID[:])
		return fmt.Errorf("bug 3, invalid book keeping for channelID %x", channelID[:])
	}

	isReader := false
	isWriter := false
	switch {
	case channelDesc.StatefulReader != nil:
		isReader = true
	case channelDesc.StatefulWriter != nil:
		isWriter = true
	}

	env, err := replicaCommon.CourierEnvelopeReplyFromBytes(plaintext)
	if err != nil {
		d.log.Errorf("failed to unmarshal courier envelope: %s", err)
		return fmt.Errorf("failed to unmarshal courier envelope: %s", err)
	}
	envHash := env.EnvelopeHash

	// DEBUG: Log envelope hash and map size when processing reply
	channelDesc.EnvelopeLock.RLock()
	mapSize := len(channelDesc.EnvelopeDescriptors)
	envelopeDesc, ok := channelDesc.EnvelopeDescriptors[*envHash]
	channelDesc.EnvelopeLock.RUnlock()

	fmt.Printf("PROCESSING REPLY ENVELOPE HASH: %x (map size: %d, exists: %t)\n", envHash[:], mapSize, ok)

	if !ok {
		d.log.Errorf("no envelope descriptor found for hash %x", envHash[:])
		return fmt.Errorf("no envelope descriptor found for hash %x", envHash[:])
	}
	privateKeyBytes := envelopeDesc.EnvelopeKey
	replicaEpoch := replicaCommon.ConvertNormalToReplicaEpoch(envelopeDesc.Epoch)
	replicaNum := envelopeDesc.ReplicaNums[env.ReplyIndex]

	privateKey, err := replicaCommon.NikeScheme.UnmarshalBinaryPrivateKey(privateKeyBytes)
	if err != nil {
		d.log.Errorf("failed to unmarshal private key: %s", err)
		return fmt.Errorf("failed to unmarshal private key: %s", err)
	}
	_, doc := d.client.CurrentDocument()
	if doc == nil {
		d.log.Errorf("no pki doc found")
		return fmt.Errorf("no pki doc found")
	}
	desc, err := replicaCommon.ReplicaNum(replicaNum, doc)
	if err != nil {
		d.log.Errorf("failed to get replica descriptor: %s", err)
		return fmt.Errorf("failed to get replica descriptor: %s", err)
	}

	replicaPubKeyBytes, ok := desc.EnvelopeKeys[replicaEpoch]
	if !ok || len(replicaPubKeyBytes) == 0 {
		d.log.Debugf("replica public key not available for epoch %d - replica may not be ready", replicaEpoch)
		return fmt.Errorf("replica public key not available for epoch %d", replicaEpoch)
	}

	replicaPubKey, err := replicaCommon.NikeScheme.UnmarshalBinaryPublicKey(replicaPubKeyBytes)
	if err != nil {
		d.log.Errorf("failed to unmarshal public key: %s", err)
		return fmt.Errorf("failed to unmarshal public key: %s", err)
	}

	if env.Payload == nil || len(env.Payload) == 0 {
		d.log.Debugf("received empty payload for envelope hash %x - no data available yet", envHash[:])
		return fmt.Errorf("no data available for read operation")
	}

	mkemPrivateKeyBytes, _ := privateKey.MarshalBinary()
	fmt.Printf("BOB DECRYPTS WITH MKEM KEY: %x\n", mkemPrivateKeyBytes[:16]) // First 16 bytes for brevity

	rawInnerMsg, err := replicaCommon.MKEMNikeScheme.DecryptEnvelope(privateKey, replicaPubKey, env.Payload)
	if err != nil {
		d.log.Errorf("failed to decrypt envelope: %s", err)
		return fmt.Errorf("failed to decrypt envelope: %s", err)
	}
	innerMsg, err := replicaCommon.ReplicaMessageReplyInnerMessageFromBytes(rawInnerMsg)
	if err != nil {
		d.log.Errorf("failed to unmarshal inner message: %s", err)
		return fmt.Errorf("failed to unmarshal inner message: %s", err)
	}

	switch {
	case innerMsg.ReplicaReadReply != nil:
		if !isReader {
			d.log.Errorf("bug 4, invalid book keeping for channelID %x", channelID[:])
			return fmt.Errorf("bug 4, invalid book keeping for channelID %x", channelID[:])
		}

		if innerMsg.ReplicaReadReply.ErrorCode != 0 {
			d.log.Debugf("replica returned error code %d for read operation", innerMsg.ReplicaReadReply.ErrorCode)
			return fmt.Errorf("replica read failed with error code %d", innerMsg.ReplicaReadReply.ErrorCode)
		}

		if innerMsg.ReplicaReadReply.Signature == nil {
			d.log.Debugf("replica returned nil signature for read operation")
			return fmt.Errorf("replica read reply has nil signature")
		}

		var boxid *[bacap.BoxIDSize]byte
		if mesgID != nil {
			channelDesc.StoredEnvelopesLock.RLock()
			storedData, exists := channelDesc.StoredEnvelopes[*mesgID]
			channelDesc.StoredEnvelopesLock.RUnlock()
			if exists {
				boxid = storedData.BoxID
				d.log.Debugf("Using stored box ID %x for message ID %x", boxid[:], mesgID[:])
			}
		}

		if boxid == nil {
			d.log.Errorf("No stored box ID found for message ID %x - cannot process reply", mesgID[:])
			return fmt.Errorf("no stored box ID found for message ID - cannot process reply")
		}

		innerplaintext, err := channelDesc.StatefulReader.DecryptNext(
			[]byte(constants.PIGEONHOLE_CTX),
			*boxid,
			innerMsg.ReplicaReadReply.Payload,
			*innerMsg.ReplicaReadReply.Signature)
		if err != nil {
			d.log.Errorf("failed to decrypt next: %s", err)
			return fmt.Errorf("failed to decrypt next: %s", err)
		}
		conn.sendResponse(&Response{
			AppID: appid,
			ReadChannelReply: &thin.ReadChannelReply{
				ChannelID: channelID,
				Payload:   innerplaintext,
			},
		})
		// possibly a BUG:
		//channelDesc.EnvelopeLock.Lock()
		//delete(channelDesc.EnvelopeDescriptors, *envHash)
		//channelDesc.EnvelopeLock.Unlock()
		return nil
	case innerMsg.ReplicaWriteReply != nil:
		if !isWriter {
			d.log.Errorf("bug 5, invalid book keeping for channelID %x", channelID[:])
			return fmt.Errorf("bug 5, invalid book keeping for channelID %x", channelID[:])
		}

		// XXX FIX ME TODO: handle write replies here, now:
		// there might be more actions to take here for example
		// if we had an ARQ we would then want to cancel our ARQ timer.
		if innerMsg.ReplicaWriteReply.ErrorCode != 0 {
			d.log.Errorf("failed to write to channel, error code: %d", innerMsg.ReplicaWriteReply.ErrorCode)
		}

		conn.sendResponse(&Response{
			AppID: appid,
			WriteChannelReply: &thin.WriteChannelReply{
				ChannelID: channelID,
			},
		})

		// possibly a BUG:
		//channelDesc.EnvelopeLock.Lock()
		//delete(channelDesc.EnvelopeDescriptors, *envHash)
		//channelDesc.EnvelopeLock.Unlock()
		return nil
	}
	d.log.Errorf("bug 6, invalid book keeping for channelID %x", channelID[:])
	return fmt.Errorf("bug 6, invalid book keeping for channelID %x", channelID[:])
}

func (d *Daemon) send(request *Request) {
	var surbKey []byte
	var rtt time.Duration
	var err error
	var now time.Time

	if request.IsARQSendOp {
		request.SURBID = &[sphinxConstants.SURBIDLength]byte{}
		_, err = rand.Reader.Read(request.SURBID[:])
		if err != nil {
			panic(err)
		}
	}

	surbKey, rtt, err = d.client.SendCiphertext(request)
	if err != nil {
		d.log.Infof("SendCiphertext error: %s", err.Error())
	}

	if request.IsARQSendOp {
		d.log.Infof("ARQ RTT %s", rtt)
	}

	if request.WithSURB {
		now = time.Now()
		// XXX  this is too aggressive, and must be at least the fetchInterval + rtt + some slopfactor to account for path delays

		fetchInterval := d.client.GetPollInterval()
		slop := time.Second
		duration := rtt + fetchInterval + slop
		replyArrivalTime := now.Add(duration)

		d.timerQueue.Push(uint64(replyArrivalTime.UnixNano()), request.SURBID)

		if !request.IsLoopDecoy {
			incomingConn := d.listener.getConnection(request.AppID)
			if incomingConn != nil {
				response := &Response{
					AppID: request.AppID,
					MessageSentEvent: &thin.MessageSentEvent{
						MessageID: request.ID,
						SURBID:    request.SURBID,
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
	if request.IsARQSendOp {
		message := &ARQMessage{
			AppID:              request.AppID,
			MessageID:          request.ID,
			SURBID:             request.SURBID,
			Payload:            request.Payload,
			DestinationIdHash:  request.DestinationIdHash,
			Retransmissions:    0,
			RecipientQueueID:   request.RecipientQueueID,
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
			id:    request.ID,
			appID: request.AppID,
		})
	}

	if request.IsSendOp {
		d.replies[*request.SURBID] = replyDescriptor{
			appID:   request.AppID,
			surbKey: surbKey,
		}
		d.replyLock.Unlock()
		return
	}

	if request.IsLoopDecoy {
		d.decoys[*request.SURBID] = replyDescriptor{
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
	echoService := echoServices[mrand.Intn(len(echoServices))]

	serviceIdHash := hash.Sum256(echoService.MixDescriptor.IdentityKey)
	payload := make([]byte, d.client.geo.UserForwardPayloadLength)
	surbID := &[sphinxConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(surbID[:])
	if err != nil {
		panic(err)

	}

	request.Payload = payload
	request.SURBID = surbID
	request.DestinationIdHash = &serviceIdHash
	request.RecipientQueueID = echoService.RecipientQueueID
	request.IsLoopDecoy = true

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
	echoService := echoServices[mrand.Intn(len(echoServices))]

	serviceIdHash := hash.Sum256(echoService.MixDescriptor.IdentityKey)
	payload := make([]byte, d.client.geo.UserForwardPayloadLength)

	request := &Request{}
	request.WithSURB = false
	request.Payload = payload
	request.DestinationIdHash = &serviceIdHash
	request.RecipientQueueID = echoService.RecipientQueueID
	request.IsDropDecoy = true

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
		ID:                message.MessageID,
		AppID:             message.AppID,
		WithSURB:          true,
		DestinationIdHash: message.DestinationIdHash,
		RecipientQueueID:  message.RecipientQueueID,
		Payload:           message.Payload,
		SURBID:            newsurbID,
		IsARQSendOp:       true,
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
