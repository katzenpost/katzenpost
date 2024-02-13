// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only
package client2

import (
	"crypto/hmac"
	"errors"
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
	RoundTripTimeSlop = (2 * time.Minute) + (15 * time.Second)

	MaxRetransmissions = 3
)

type handleAckCtx struct {
	surbid  *[sConstants.SURBIDLength]byte
	replyCh chan *replyDescriptor
}

type hasCtx struct {
	surbid  *[sConstants.SURBIDLength]byte
	replyCh chan bool
}

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
	gcSurbIDCh chan *[sConstants.SURBIDLength]byte
	surbIDMap  map[[sConstants.SURBIDLength]byte]*ARQMessage

	sphinxComposerSender SphinxComposerSender
	sentEventSender      SentEventSender

	sendCh   chan *sendCtx
	resendCh chan *[sConstants.SURBIDLength]byte

	hasCh      chan *hasCtx
	hasReplyCh chan bool

	handleAckCh chan *handleAckCtx
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
		hasCh:                make(chan *hasCtx, 0),
		handleAckCh:          make(chan *handleAckCtx, 0),
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
		response := &Response{
			AppID: message.AppID,
			MessageReplyEvent: &thin.MessageReplyEvent{
				MessageID: message.MessageID,
				Err:       errors.New("Max retries met."),
			},
		}
		a.sentEventSender.SentEvent(response)
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
	replyCh := make(chan bool, 0)
	a.hasCh <- &hasCtx{
		surbid:  surbID,
		replyCh: replyCh,
	}
	ok := <-replyCh
	return ok
}

// HandleACK removes the map entry for the given SURB ID AND returns
// the APP ID and SURB Key so that the reply and be decrypted and routed
// to the correct application.
func (a *ARQ) HandleAck(surbID *[sConstants.SURBIDLength]byte) (*replyDescriptor, error) {
	a.log.Info("HandleAck")

	replyCh := make(chan *replyDescriptor, 0)
	a.handleAckCh <- &handleAckCtx{
		surbid:  surbID,
		replyCh: replyCh,
	}
	replyDesc := <-replyCh

	return replyDesc, nil
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
	a.sendCh <- &sendCtx{
		arqMessage: message,
		pkt:        pkt,
	}

	return rtt, nil
}

func (a *ARQ) egressWorker() {
	for {
		select {
		case <-a.HaltCh():
			return
		case surbID := <-a.resendCh:
			a.doResend(surbID)
		case ctx := <-a.sendCh:
			message := ctx.arqMessage
			a.surbIDMap[*message.SURBID] = message
			myRtt := message.SentAt.Add(message.ReplyETA)
			myRtt = myRtt.Add(RoundTripTimeSlop)
			priority := uint64(myRtt.UnixNano())
			a.timerQueue.Push(priority, message.SURBID)
			a.doSend(ctx)
		case ctx := <-a.hasCh:
			_, ok := a.surbIDMap[*ctx.surbid]
			ctx.replyCh <- ok
		case ctx := <-a.handleAckCh:
			replyDesc, err := a.doHandleAck(ctx.surbid)
			if err != nil {
				continue
			}
			ctx.replyCh <- replyDesc
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

func (a *ARQ) doHandleAck(surbid *[sConstants.SURBIDLength]byte) (*replyDescriptor, error) {
	m, ok := a.surbIDMap[*surbid]
	if ok {
		a.log.Infof("HandleAck ID %x", m.MessageID[:])
	} else {
		a.log.Error("HandleAck: failed to find SURB ID in ARQ map")
		return nil, errors.New("failed to find SURB ID in ARQ map")
	}

	delete(a.surbIDMap, *surbid)
	peeked := a.timerQueue.Peek()
	if peeked != nil {
		peekSurbId := peeked.Value.(*[sConstants.SURBIDLength]byte)
		if hmac.Equal(surbid[:], peekSurbId[:]) {
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
