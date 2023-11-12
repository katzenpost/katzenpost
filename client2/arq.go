// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only
package client2

import (
	"errors"
	"io"
	"sync"
	"time"

	"github.com/charmbracelet/log"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

const (
	// MessageIDLength is the length of a message ID in bytes.
	MessageIDLength = 16

	// RoundTripTimeSlop is the slop added to the expected packet
	// round trip timeout threshold.
	RoundTripTimeSlop = 3 * time.Second
)

type SphinxComposerSender interface {
	ComposeSphinxPacket(request *Request) ([]byte, []byte, time.Duration, error)
	SendSphinxPacket(pkt []byte) error
}

// ARQMessage is used by ARQ.
type ARQMessage struct {

	// AppID identifies the application sending/receiving the message/reply.
	AppID uint64

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

	// SURBDecryptionKey is the SURB decryption keys
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
	log *log.Logger

	timerQueue *TimerQueue
	lock       sync.RWMutex
	gcSurbIDCh chan *[sConstants.SURBIDLength]byte
	surbIDMap  map[[sConstants.SURBIDLength]byte]*ARQMessage

	sphinxComposerSender SphinxComposerSender
}

// NewARQ creates a new ARQ.
func NewARQ(sphinxComposerSender SphinxComposerSender, logbackend io.Writer) *ARQ {
	log := log.NewWithOptions(logbackend, log.Options{
		ReportTimestamp: true,
		Level:           log.DebugLevel,
		Prefix:          "_ARQ_",
	})
	log.Info("NewARQ")
	return &ARQ{
		log:                  log,
		gcSurbIDCh:           make(chan *[sConstants.SURBIDLength]byte),
		surbIDMap:            make(map[[sConstants.SURBIDLength]byte]*ARQMessage),
		sphinxComposerSender: sphinxComposerSender,
	}
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
		a.resend(surbID)
	})
	a.timerQueue.Start()
}

// Stop stops the ARQ's timer queue worker thread.
func (a *ARQ) Stop() {
	a.log.Info("Stop")
	a.timerQueue.Halt()
	a.timerQueue.Wait()
}

func (a *ARQ) resend(surbID *[sConstants.SURBIDLength]byte) {
	a.log.Info("resend")

	a.lock.Lock()
	message, ok := a.surbIDMap[*surbID]
	if ok {
		delete(a.surbIDMap, *surbID)
		newsurbID := &[sConstants.SURBIDLength]byte{}
		_, err := rand.Reader.Read(newsurbID[:])
		if err != nil {
			panic(err)
		}

		pkt, k, rtt, err := a.sphinxComposerSender.ComposeSphinxPacket(&Request{
			WithSURB:          true,
			SURBID:            newsurbID,
			DestinationIdHash: message.DestinationIdHash,
			RecipientQueueID:  message.RecipientQueueID,
			Payload:           message.Payload,
			IsSendOp:          true,
		})
		if err != nil {
			panic(err)
		}

		message.SURBID = newsurbID
		message.SURBDecryptionKeys = k
		message.ReplyETA = rtt
		message.SentAt = time.Now()
		message.Retransmissions += 1

		a.surbIDMap[*newsurbID] = message
		priority := uint64(message.SentAt.Add(message.ReplyETA).Add(RoundTripTimeSlop).UnixNano())
		a.timerQueue.Push(priority, surbID)

		err = a.sphinxComposerSender.SendSphinxPacket(pkt)
		if err != nil {
			a.log.Errorf("gc sphinx composer failure: %s", err.Error())
		}

	} else {
		a.log.Error("gc SURB ID not found")
	}
	a.lock.Unlock()
}

// Has checks if a given SURB ID exists.
func (a *ARQ) Has(surbID *[sConstants.SURBIDLength]byte) bool {
	a.log.Info("Has")

	a.lock.RLock()
	_, ok := a.surbIDMap[*surbID]
	a.lock.RUnlock()
	return ok
}

// HandleACK removes the map entry for the given SURB ID AND returns
// the APP ID and SURB Key so that the reply and be decrypted and routed
// to the correct application.
func (a *ARQ) HandleAck(surbID *[sConstants.SURBIDLength]byte) (*replyDescriptor, error) {
	a.lock.Lock()

	m, ok := a.surbIDMap[*surbID]
	if !ok {
		a.log.Error("failed to find SURB ID in ARQ map")
		return nil, errors.New("failed to find SURB ID in ARQ map")
	}
	delete(a.surbIDMap, *surbID)

	a.lock.Unlock()

	return &replyDescriptor{
		ID:      m.MessageID,
		appID:   m.AppID,
		surbKey: m.SURBDecryptionKeys,
	}, nil
}

// Send sends a message asynchronously. Sometime later, perhaps a reply will be received.
func (a *ARQ) Send(appid uint64, id *[MessageIDLength]byte, payload []byte, providerHash *[32]byte, queueID []byte) error {
	a.log.Info("Send")

	a.lock.Lock()
	defer a.lock.Unlock()

	surbID := &[sConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(surbID[:])
	if err != nil {
		panic(err)
	}

	pkt, k, rtt, err := a.sphinxComposerSender.ComposeSphinxPacket(&Request{
		WithSURB:          true,
		SURBID:            surbID,
		DestinationIdHash: providerHash,
		RecipientQueueID:  queueID,
		Payload:           payload,
		IsSendOp:          true,
	})
	if err != nil {
		panic(err)
	}

	message := &ARQMessage{
		AppID:              appid,
		MessageID:          id,
		SURBID:             surbID,
		Payload:            payload,
		SURBDecryptionKeys: k,
		SentAt:             time.Now(),
		ReplyETA:           rtt,
	}
	a.surbIDMap[*surbID] = message
	p := time.Duration(message.ReplyETA + RoundTripTimeSlop)
	a.log.Infof("Push to timer queue with priorit %s", p)
	priority := uint64(message.SentAt.Add(message.ReplyETA).Add(RoundTripTimeSlop).UnixNano())

	a.timerQueue.Push(priority, surbID)

	err = a.sphinxComposerSender.SendSphinxPacket(pkt)
	if err != nil {
		return err
	}

	return nil
}
