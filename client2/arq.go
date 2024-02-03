// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only
package client2

import (
	"crypto/hmac"
	"errors"
	"sync"
	"time"

	"github.com/charmbracelet/log"

	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/worker"
)

const (
	// MessageIDLength is the length of a message ID in bytes.
	MessageIDLength = 16

	// RoundTripTimeSlop is the slop added to the expected packet
	// round trip timeout threshold.
	RoundTripTimeSlop = (1 * time.Minute) + (30 * time.Second)

	MaxRetransmissions = 3
)

type SphinxComposerSender interface {
	SendPacket(pkt []byte) error
	ComposeSphinxPacket(request *Request) (pkt []byte, surbkey []byte, rtt time.Duration, err error)
}

type SentEventSender interface {
	SentEvent(response *Response)
}

type sendCtx struct {
	arqMessage *ARQMessage
	pkt        []byte
}

// ARQMessage is used by ARQ.
type ARQMessage struct {

	// AppID identifies the application sending/receiving the message/reply.
	AppID *[AppIDLength]byte

	// MessageID is the unique message identifier
	MessageID *[MessageIDLength]byte

	// DestinationIdHash is 32 byte hash of the destination Provider's
	// identity public key.
	DestinationIdHash *[32]byte

	// RecipientQueueID is the queue identity which will receive the message.
	RecipientQueueID []byte

	// Payload is the message payload
	Payload []byte

	// SURBID is the SURB identifier.
	SURBID *[sConstants.SURBIDLength]byte

	// SURBDecryptionKeys is the SURB decryption keys
	SURBDecryptionKeys []byte

	// Retransmissions counts the number of times the message has been retransmitted.
	Retransmissions uint32

	// SentAt contains the time the message was sent.
	SentAt time.Time

	// ReplyETA is the expected round trip time to receive a response.
	ReplyETA time.Duration
}

// ARQ is a very simple Automatic Repeat reQuest error correction stategy.
// Lost packets will be retransmitted. Not an optimized design.
type ARQ struct {
	worker.Worker

	log *log.Logger

	timerQueue *TimerQueue
	lock       sync.RWMutex
	gcSurbIDCh chan *[sConstants.SURBIDLength]byte
	surbIDMap  map[[sConstants.SURBIDLength]byte]*ARQMessage

	sphinxComposerSender SphinxComposerSender
	sentEventSender      SentEventSender

	sendCh   chan *sendCtx
	resendCh chan *[sConstants.SURBIDLength]byte
}

// NewARQ creates a new ARQ.
func NewARQ(sphinxComposerSender SphinxComposerSender, sentEventSender SentEventSender, mylog *log.Logger) *ARQ {
	arqlog := mylog.WithPrefix("_ARQ_")
	arqlog.Info("NewARQ")
	return &ARQ{
		log:                  arqlog,
		gcSurbIDCh:           make(chan *[sConstants.SURBIDLength]byte),
		surbIDMap:            make(map[[sConstants.SURBIDLength]byte]*ARQMessage),
		sphinxComposerSender: sphinxComposerSender,
		sentEventSender:      sentEventSender,
		sendCh:               make(chan *sendCtx, 2),
		resendCh:             make(chan *[sConstants.SURBIDLength]byte, 2),
	}
}

// Stop stops the ARQ's timer queue worker thread.
func (a *ARQ) Stop() {
	a.log.Info("Stop")
	a.timerQueue.Halt()
	a.timerQueue.Wait()
}

// Start starts the ARQ worker thread. You MUST start before using.
func (a *ARQ) Start() {
	a.log.Info("Start")

	a.timerQueue = NewTimerQueue(func(rawSurbID interface{}) {
		a.log.Info("TimerQueue callback!")
		surbID, ok := rawSurbID.(*[sConstants.SURBIDLength]byte)
		if !ok {
			panic("wtf, failed type assertion!")
		}
		a.log.Warn("BEFORE resend")
		a.resend(surbID)
		a.log.Warn("AFTER resend")
	})

	a.timerQueue.Start()
	a.log.Info("Starting timerQueue finished.")

	a.Go(a.egressWorker)
}

func (a *ARQ) resend(surbID *[sConstants.SURBIDLength]byte) {
	select {
	case <-a.HaltCh():
		return
	case a.resendCh <- surbID:
	}
}

func (a *ARQ) doResend(surbID *[sConstants.SURBIDLength]byte) {
	a.log.Info("resend start")
	defer a.log.Info("resend end")

	a.lock.Lock()

	message, ok := a.surbIDMap[*surbID]
	// NOTE(david): if the surbIDMap entry is not found
	// it means that HandleAck was already called with the
	// given SURB ID.
	if !ok {
		a.log.Warnf("SURB ID %x NOT FOUND. Aborting resend.", surbID[:])
		return
	}
	if (message.Retransmissions + 1) > MaxRetransmissions {
		a.log.Warn("Max retries met.")
		return
	}

	a.log.Warnf("resend ----------------- REMOVING SURB ID %x", surbID[:])
	delete(a.surbIDMap, *surbID)

	newsurbID := &[sConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(newsurbID[:])
	if err != nil {
		panic(err)
	}
	pkt, k, rtt, err := a.sphinxComposerSender.ComposeSphinxPacket(&Request{
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
		a.log.Errorf("failed to send sphinx packet: %s", err.Error())
	}

	message.SURBID = newsurbID
	message.SURBDecryptionKeys = k
	message.ReplyETA = rtt
	message.SentAt = time.Now()
	message.Retransmissions += 1

	a.surbIDMap[*newsurbID] = message
	a.lock.Unlock()

	a.log.Warnf("resend PUTTING INTO MAP, NEW SURB ID %x", newsurbID[:])

	myRtt := message.SentAt.Add(message.ReplyETA)
	myRtt = myRtt.Add(RoundTripTimeSlop)
	priority := uint64(myRtt.UnixNano())
	a.timerQueue.Push(priority, newsurbID)

	a.sendCh <- &sendCtx{
		arqMessage: message,
		pkt:        pkt,
	}
}

// Has checks if a given SURB ID exists.
func (a *ARQ) Has(surbID *[sConstants.SURBIDLength]byte) bool {
	a.log.Info("Has")

	a.lock.RLock()
	a.log.Info("Has got lock")
	m, ok := a.surbIDMap[*surbID]
	a.lock.RUnlock()

	if ok {
		a.log.Infof("Has SURBID %x message ID %x", surbID[:], m.MessageID[:])
	} else {
		a.log.Infof("Has SURB NOT FOUND! SURBID %x", surbID[:])
	}
	return ok
}

// HandleACK removes the map entry for the given SURB ID AND returns
// the APP ID and SURB Key so that the reply and be decrypted and routed
// to the correct application.
func (a *ARQ) HandleAck(surbID *[sConstants.SURBIDLength]byte) (*replyDescriptor, error) {
	a.log.Info("HandleAck")
	a.lock.Lock()

	m, ok := a.surbIDMap[*surbID]
	if ok {
		a.log.Infof("HandleAck ID %x", m.MessageID[:])
	} else {
		a.log.Error("HandleAck: failed to find SURB ID in ARQ map")
		a.lock.Unlock()
		return nil, errors.New("failed to find SURB ID in ARQ map")
	}

	a.log.Warnf("HandleAck ----------------- REMOVING SURB ID %x", surbID[:])
	delete(a.surbIDMap, *surbID)
	a.lock.Unlock()

	peeked := a.timerQueue.Peek()
	if peeked != nil {
		peekSurbId := peeked.Value.(*[sConstants.SURBIDLength]byte)
		if hmac.Equal(surbID[:], peekSurbId[:]) {
			a.log.Warn("HandleAck Popped")
			a.timerQueue.Pop()
		}
	}

	return &replyDescriptor{
		ID:      m.MessageID,
		appID:   m.AppID,
		surbKey: m.SURBDecryptionKeys,
	}, nil
}

// Send sends a message asynchronously. Sometime later, perhaps a reply will be received.
func (a *ARQ) Send(appid *[AppIDLength]byte, id *[MessageIDLength]byte, payload []byte, providerHash *[32]byte, queueID []byte) (time.Duration, error) {
	surbID := &[sConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(surbID[:])
	if err != nil {
		panic(err)
	}

	pkt, k, rtt, err := a.sphinxComposerSender.ComposeSphinxPacket(&Request{
		AppID:             appid,
		WithSURB:          true,
		SURBID:            surbID,
		DestinationIdHash: providerHash,
		RecipientQueueID:  queueID,
		Payload:           payload,
		IsARQSendOp:       true,
	})
	if err != nil {
		return 0, err
	}

	message := &ARQMessage{
		AppID:              appid,
		MessageID:          id,
		SURBID:             surbID,
		Payload:            payload,
		DestinationIdHash:  providerHash,
		Retransmissions:    0,
		RecipientQueueID:   queueID,
		SURBDecryptionKeys: k,
		SentAt:             time.Now(),
		ReplyETA:           rtt,
	}
	a.log.Warnf("Send PUTTING INTO MAP, NEW SURB ID %x", surbID[:])
	a.lock.Lock()
	a.surbIDMap[*surbID] = message
	a.lock.Unlock()

	a.sendCh <- &sendCtx{
		arqMessage: message,
		pkt:        pkt,
	}

	myRtt := message.SentAt.Add(message.ReplyETA)
	myRtt = myRtt.Add(RoundTripTimeSlop)
	priority := uint64(myRtt.UnixNano())
	a.timerQueue.Push(priority, surbID)

	return rtt, nil
}

func (a *ARQ) egressWorker() {
	for {
		select {
		case <-a.HaltCh():
			return
		case surbID := <-a.resendCh:
			a.doResend(surbID)
		case r := <-a.sendCh:
			a.doSend(r)
		}
	}
}

func (a *ARQ) doSend(s *sendCtx) {
	err := a.sphinxComposerSender.SendPacket(s.pkt)
	response := &Response{
		AppID: s.arqMessage.AppID,
		MessageSentEvent: &thin.MessageSentEvent{
			MessageID: s.arqMessage.MessageID,
			SURBID:    s.arqMessage.SURBID,
			SentAt:    time.Now(),
			ReplyETA:  s.arqMessage.ReplyETA,
			Err:       err,
		},
	}
	a.sentEventSender.SentEvent(response)
}
