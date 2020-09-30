// session.go - mixnet client session
// Copyright (C) 2018  David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package client

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	mrand "math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/katzenpost/client/config"
	cConstants "github.com/katzenpost/client/constants"
	"github.com/katzenpost/client/internal/pkiclient"
	"github.com/katzenpost/client/utils"
	coreConstants "github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/sphinx"
	sConstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/minclient"
	"gopkg.in/eapache/channels.v1"
	"gopkg.in/op/go-logging.v1"
)

// Session is the struct type that keeps state for a given session.
type Session struct {
	worker.Worker

	cfg       *config.Config
	pkiClient pki.Client
	minclient *minclient.Client
	log       *logging.Logger

	fatalErrCh chan error
	opCh       chan workerOp

	eventCh   channels.Channel
	EventSink chan Event

	linkKey   *ecdh.PrivateKey
	onlineAt  time.Time
	hasPKIDoc bool

	egressQueue EgressQueue

	surbIDMap        sync.Map // [sConstants.SURBIDLength]byte -> *Message
	sentWaitChanMap  sync.Map // MessageID -> chan *Message
	replyWaitChanMap sync.Map // MessageID -> chan []byte

	decoyLoopTally uint64
}

// New establishes a session with provider using key.
// This method will block until session is connected to the Provider.
func NewSession(
	ctx context.Context,
	fatalErrCh chan error,
	logBackend *log.Backend,
	cfg *config.Config,
	linkKey *ecdh.PrivateKey) (*Session, error) {
	var err error

	// create a pkiclient for our own client lookups
	// AND create a pkiclient for minclient's use
	proxyCfg := cfg.UpstreamProxyConfig()
	pkiClient, err := cfg.NewPKIClient(logBackend, proxyCfg)
	if err != nil {
		return nil, err
	}

	// create a pkiclient for minclient's use
	pkiClient2, err := cfg.NewPKIClient(logBackend, proxyCfg)
	if err != nil {
		return nil, err
	}
	pkiCacheClient := pkiclient.New(pkiClient2)

	clientLog := logBackend.GetLogger(fmt.Sprintf("%s@%s_client", cfg.Account.User, cfg.Account.Provider))

	s := &Session{
		cfg:         cfg,
		linkKey:     linkKey,
		pkiClient:   pkiClient,
		log:         clientLog,
		fatalErrCh:  fatalErrCh,
		eventCh:     channels.NewInfiniteChannel(),
		EventSink:   make(chan Event),
		opCh:        make(chan workerOp, 8),
		egressQueue: new(Queue),
	}
	// Configure and bring up the minclient instance.
	clientCfg := &minclient.ClientConfig{
		User:                cfg.Account.User,
		Provider:            cfg.Account.Provider,
		ProviderKeyPin:      cfg.Account.ProviderKeyPin,
		LinkKey:             s.linkKey,
		LogBackend:          logBackend,
		PKIClient:           pkiCacheClient,
		OnConnFn:            s.onConnection,
		OnMessageFn:         s.onMessage,
		OnACKFn:             s.onACK,
		OnDocumentFn:        s.onDocument,
		DialContextFn:       proxyCfg.ToDialContext("authority"),
		PreferedTransports:  cfg.Debug.PreferedTransports,
		MessagePollInterval: time.Duration(cfg.Debug.PollingInterval) * time.Millisecond,
		EnableTimeSync:      false, // Be explicit about it.
	}

	s.Go(s.eventSinkWorker)
	s.Go(s.garbageCollectionWorker)

	s.minclient, err = minclient.New(clientCfg)
	if err != nil {
		return nil, err
	}

	// block until we get the first PKI document
	// and then set our timers accordingly
	err = s.awaitFirstPKIDoc(ctx)
	if err != nil {
		return nil, err
	}
	s.Go(s.worker)
	return s, nil
}

func (s *Session) eventSinkWorker() {
	for {
		select {
		case <-s.HaltCh():
			s.log.Debugf("Event sink worker terminating gracefully.")
			return
		case e := <-s.eventCh.Out():
			select {
			case s.EventSink <- e.(Event):
			case <-s.HaltCh():
				s.log.Debugf("Event sink worker terminating gracefully.")
				return
			}
		}
	}
}

func (s *Session) garbageCollectionWorker() {
	timer := time.NewTimer(cConstants.GarbageCollectionInterval)
	defer timer.Stop()
	for {
		select {
		case <-s.HaltCh():
			s.log.Debugf("Garbage collection worker terminating gracefully.")
			return
		case <-timer.C:
			s.garbageCollect()
			timer.Reset(cConstants.GarbageCollectionInterval)
		}
	}
}

func (s *Session) garbageCollect() {
	s.log.Debug("Running garbage collection process.")
	// [sConstants.SURBIDLength]byte -> *Message
	surbIDMapRange := func(rawSurbID, rawMessage interface{}) bool {
		surbID := rawSurbID.([sConstants.SURBIDLength]byte)
		message := rawMessage.(*Message)
		if time.Now().After(message.SentAt.Add(message.ReplyETA).Add(cConstants.RoundTripTimeSlop)) {
			s.log.Debug("Garbage collecting SURB ID Map entry for Message ID %x", message.ID)
			s.surbIDMap.Delete(surbID)
			s.eventCh.In() <- &MessageIDGarbageCollected{
				MessageID: message.ID,
			}
		}
		return true
	}
	s.surbIDMap.Range(surbIDMapRange)
}

func (s *Session) awaitFirstPKIDoc(ctx context.Context) error {
	for {
		var qo workerOp
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.HaltCh():
			s.log.Debugf("Await first pki doc worker terminating gracefully")
			return errors.New("terminating gracefully")
		case <-time.After(time.Duration(s.cfg.Debug.InitialMaxPKIRetrievalDelay) * time.Second):
			return errors.New("timeout failure awaiting first PKI document")
		case qo = <-s.opCh:
		}
		switch op := qo.(type) {
		case opNewDocument:
			// Determine if PKI doc is valid. If not then abort.
			err := s.isDocValid(op.doc)
			if err != nil {
				s.fatalErrCh <- fmt.Errorf("aborting, PKI doc is not valid for our decoy traffic use case: %v", err)
				return err
			}
			return nil
		default:
			continue
		}
	}
	// NOT REACHED
}

// GetService returns a randomly selected service
// matching the specified service name
func (s *Session) GetService(serviceName string) (*utils.ServiceDescriptor, error) {
	doc := s.minclient.CurrentDocument()
	if doc == nil {
		return nil, errors.New("pki doc is nil")
	}
	serviceDescriptors := utils.FindServices(serviceName, doc)
	if len(serviceDescriptors) == 0 {
		return nil, errors.New("error, GetService failure, service not found in pki doc")
	}
	return &serviceDescriptors[mrand.Intn(len(serviceDescriptors))], nil
}

// OnConnection will be called by the minclient api
// upon connection change status to the Provider
func (s *Session) onConnection(err error) {
	s.log.Debugf("onConnection %v", err)
	s.eventCh.In() <- &ConnectionStatusEvent{
		IsConnected: err == nil,
		Err:         err,
	}
	s.opCh <- opConnStatusChanged{
		isConnected: err == nil,
	}
}

// OnMessage will be called by the minclient api
// upon receiving a message
func (s *Session) onMessage(ciphertextBlock []byte) error {
	s.log.Debugf("OnMessage")
	return nil
}

func (s *Session) incrementDecoyLoopTally() {
	atomic.AddUint64(&s.decoyLoopTally, 1)
}

func (s *Session) decrementDecoyLoopTally() {
	atomic.AddUint64(&s.decoyLoopTally, ^uint64(0))
}

// OnACK is called by the minclient api when we receive a SURB reply message.
func (s *Session) onACK(surbID *[sConstants.SURBIDLength]byte, ciphertext []byte) error {
	idStr := fmt.Sprintf("[%v]", hex.EncodeToString(surbID[:]))
	s.log.Infof("OnACK with SURBID %x", idStr)

	rawMessage, ok := s.surbIDMap.Load(*surbID)
	if !ok {
		s.log.Debug("Strange, received reply with unexpected SURBID")
		return nil
	}
	s.surbIDMap.Delete(*surbID)
	msg := rawMessage.(*Message)
	plaintext, err := sphinx.DecryptSURBPayload(ciphertext, msg.Key)
	if err != nil {
		s.log.Infof("Discarding SURB Reply, decryption failure: %s", err)
		return nil
	}
	if len(plaintext) != coreConstants.ForwardPayloadLength {
		s.log.Warningf("Discarding SURB %v: Invalid payload size: %v", idStr, len(plaintext))
		return nil
	}
	if msg.WithSURB && msg.IsDecoy {
		s.decrementDecoyLoopTally()
		return nil
	}

	if msg.IsBlocking {
		replyWaitChanRaw, ok := s.replyWaitChanMap.Load(*msg.ID)
		if !ok {
			//XXX: this can happen if a SURB-ACK arrives after a call to BlockingSendUnreliableMessage has timed-out
			// because the session.surbIDMap has not been deleted or garbage collected
			s.log.Warningf("Discarding surb %v for blocking message %x : caller likely timed-out", idStr, msg.ID)
			return nil
		}
		replyWaitChan := replyWaitChanRaw.(chan []byte)
		replyWaitChan <- plaintext[2:]
	} else {
		s.eventCh.In() <- &MessageReplyEvent{
			MessageID: msg.ID,
			Payload:   plaintext[2:],
			Err:       nil,
		}
	}
	return nil
}

func (s *Session) onDocument(doc *pki.Document) {
	s.log.Debugf("onDocument(): Epoch %v", doc.Epoch)
	s.hasPKIDoc = true
	s.opCh <- opNewDocument{
		doc: doc,
	}
	s.eventCh.In() <- &NewDocumentEvent{
		Document: doc,
	}
}

func (s *Session) CurrentDocument() *pki.Document {
	return s.minclient.CurrentDocument()
}

func (s *Session) GetReunionConfig() *config.Reunion {
	return s.cfg.Reunion
}

func (s *Session) GetPandaConfig() *config.Panda {
	return s.cfg.Panda
}

func (s *Session) Shutdown() {
	s.Halt()
	s.minclient.Shutdown()
	s.minclient.Wait()
}
