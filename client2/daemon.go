// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"crypto/hmac"
	"errors"
	mrand "math/rand"
	"path/filepath"
	"sync"
	"time"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/rand"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/client2/common"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/worker"
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
	surbID     *[constants.SURBIDLength]byte
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

	replies   map[[sConstants.SURBIDLength]byte]replyDescriptor
	decoys    map[[sConstants.SURBIDLength]byte]replyDescriptor
	replyLock *sync.Mutex

	timerQueue *TimerQueue
	ingressCh  chan *sphinxReply
	gcSurbIDCh chan *[sConstants.SURBIDLength]byte

	gcTimerQueue *TimerQueue
	gcReplyCh    chan *gcReply

	arqTimerQueue *TimerQueue
	arqSurbIDMap  map[[sConstants.SURBIDLength]byte]*ARQMessage
	arqResendCh   chan *[sConstants.SURBIDLength]byte

	haltOnce sync.Once
}

func NewDaemon(cfg *config.Config) (*Daemon, error) {
	egressSize := 2
	ingressSize := 200
	d := &Daemon{
		cfg:          cfg,
		egressCh:     make(chan *Request, egressSize),
		ingressCh:    make(chan *sphinxReply, ingressSize),
		replies:      make(map[[sConstants.SURBIDLength]byte]replyDescriptor),
		decoys:       make(map[[sConstants.SURBIDLength]byte]replyDescriptor),
		gcSurbIDCh:   make(chan *[sConstants.SURBIDLength]byte),
		gcReplyCh:    make(chan *gcReply),
		replyLock:    new(sync.Mutex),
		arqSurbIDMap: make(map[[sConstants.SURBIDLength]byte]*ARQMessage),
		arqResendCh:  make(chan *[sConstants.SURBIDLength]byte, 2),
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
	d.log.Debug("Stopping timerQueue")
	d.timerQueue.Halt()
	d.log.Debug("Stopping gcTimerQueue")
	d.gcTimerQueue.Halt()
	d.log.Debug("Stopping arqTimerQueue")
	d.arqTimerQueue.Halt()

	d.log.Debug("Stopping client")
	d.client.Shutdown()
	d.Halt() // shutdown ingressWorker and egressWorker
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
		surbID, ok := rawSurbID.(*[sConstants.SURBIDLength]byte)
		if !ok {
			panic("wtf, failed type assertion!")
		}
		select {
		case d.gcSurbIDCh <- surbID:
		case <-d.HaltCh():
			return
		}
	})
	d.timerQueue.Start()
	d.arqTimerQueue = NewTimerQueue(func(rawSurbID interface{}) {
		d.log.Info("ARQ TimerQueue callback!")
		surbID, ok := rawSurbID.(*[sConstants.SURBIDLength]byte)
		if !ok {
			panic("wtf, failed type assertion!")
		}
		d.log.Warning("BEFORE ARQ resend")
		d.arqResend(surbID)
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
		}
	})
	d.gcTimerQueue.Start()

	d.Go(d.ingressWorker)
	d.Go(d.egressWorker)

	return d.client.Start()
}

func (d *Daemon) onDocument(doc *cpki.Document) {
	slopFactor := 0.8
	pollProviderMsec := time.Duration((1.0 / (doc.LambdaP + doc.LambdaL)) * slopFactor * float64(time.Millisecond))
	d.client.SetPollInterval(pollProviderMsec)
	d.listener.updateFromPKIDoc(doc)
}

func (d *Daemon) proxyReplies(surbID *[constants.SURBIDLength]byte, ciphertext []byte) error {
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
			case request.IsLoopDecoy == true:
				d.sendLoopDecoy(request)
			case request.IsDropDecoy == true:
				d.sendDropDecoy()
			case request.IsSendOp == true:
				d.send(request)
			case request.IsARQSendOp == true:
				d.send(request)
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
	isDecoy := false

	d.replyLock.Lock()
	desc, ok := d.replies[*reply.surbID]
	if !ok {
		desc, ok = d.decoys[*reply.surbID]
		if ok {
			isDecoy = true
		} else {
			arqMessage, ok := d.arqSurbIDMap[*reply.surbID]
			if ok {
				desc = replyDescriptor{
					ID:      arqMessage.MessageID,
					appID:   arqMessage.AppID,
					surbKey: arqMessage.SURBDecryptionKeys,
				}
				peeked := d.arqTimerQueue.Peek()
				if peeked != nil {
					peekSurbId := peeked.Value.(*[sConstants.SURBIDLength]byte)
					if hmac.Equal(arqMessage.SURBID[:], peekSurbId[:]) {
						d.arqTimerQueue.Pop()
					}
				}
			} else {
				d.replyLock.Unlock()
				return
			}
		}

	}
	delete(d.replies, *reply.surbID)
	delete(d.decoys, *reply.surbID)
	delete(d.arqSurbIDMap, *reply.surbID)
	d.replyLock.Unlock()

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
	conn.sendResponse(&Response{
		AppID: desc.appID,
		MessageReplyEvent: &thin.MessageReplyEvent{
			MessageID: desc.ID,
			SURBID:    reply.surbID,
			Payload:   plaintext,
		},
	})

}

func (d *Daemon) send(request *Request) {
	surbKey := []byte{}
	var rtt time.Duration
	var err error
	var now time.Time

	if request.IsARQSendOp == true {
		request.SURBID = &[sConstants.SURBIDLength]byte{}
		_, err = rand.Reader.Read(request.SURBID[:])
		if err != nil {
			panic(err)
		}
	}

	surbKey, rtt, err = d.client.SendCiphertext(request)
	if err != nil {
		d.log.Infof("SendCiphertext error: %s", err.Error())
	}

	if request.IsARQSendOp == true {
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

		if request.IsLoopDecoy == false {
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
	if request.IsARQSendOp == true {
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

	doc := d.client.CurrentDocument()
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
	surbID := &[sConstants.SURBIDLength]byte{}
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
	doc := d.client.CurrentDocument()
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

func (d *Daemon) arqResend(surbID *[sConstants.SURBIDLength]byte) {
	select {
	case <-d.HaltCh():
		return
	case d.arqResendCh <- surbID:
	}
}

func (d *Daemon) arqDoResend(surbID *[sConstants.SURBIDLength]byte) {
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
				Err:       errors.New("Max retries met."),
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

	newsurbID := &[sConstants.SURBIDLength]byte{}
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
