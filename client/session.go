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
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/blake2b"
	"gopkg.in/eapache/channels.v1"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client/config"
	cConstants "github.com/katzenpost/katzenpost/client/constants"
	"github.com/katzenpost/katzenpost/client/utils"
	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/minclient"
)

// Session is the struct type that keeps state for a given session.
type Session struct {
	worker.Worker

	geo    *geo.Geometry
	sphinx *sphinx.Sphinx

	cfg        *config.Config
	pkiClient  pki.Client
	minclient  *minclient.Client
	provider   *pki.MixDescriptor
	log        *logging.Logger
	logBackend *log.Backend

	fatalErrCh chan error
	opCh       chan workerOp

	eventCh   channels.Channel
	EventSink chan Event

	linkKey   kem.PrivateKey
	onlineAt  time.Time
	hasPKIDoc bool
	newPKIDoc chan bool

	egressQueue EgressQueue
	timerQ      *TimerQueue

	surbIDMap        sync.Map // [sConstants.SURBIDLength]byte -> *Message
	sentWaitChanMap  sync.Map // MessageID -> chan *Message
	replyWaitChanMap sync.Map // MessageID -> chan []byte

	decoyLoopTally uint64
}

// New establishes a session with provider using key.
// This method will block until session is connected to the Provider.
func NewSession(
	ctx context.Context,
	pkiClient pki.Client,
	cachedDoc *pki.Document,
	fatalErrCh chan error,
	logBackend *log.Backend,
	cfg *config.Config,
	linkKey kem.PrivateKey,
	provider *pki.MixDescriptor) (*Session, error) {

	clientLog := logBackend.GetLogger(fmt.Sprintf("%s_client", provider.Name))

	mysphinx, err := sphinx.FromGeometry(cfg.SphinxGeometry)
	if err != nil {
		return nil, err
	}

	s := &Session{
		geo:         cfg.SphinxGeometry,
		sphinx:      mysphinx,
		cfg:         cfg,
		linkKey:     linkKey,
		provider:    provider,
		pkiClient:   pkiClient,
		logBackend:  logBackend,
		log:         clientLog,
		fatalErrCh:  fatalErrCh,
		eventCh:     channels.NewInfiniteChannel(),
		newPKIDoc:   make(chan bool),
		EventSink:   make(chan Event),
		opCh:        make(chan workerOp, 8),
		egressQueue: new(Queue),
	}
	// Configure the timerQ instance
	s.timerQ = NewTimerQueue(s)
	// Configure and bring up the minclient instance.
	blob, err := s.linkKey.Public().MarshalBinary()
	if err != nil {
		return nil, err
	}
	idHash := blake2b.Sum256(blob)
	// A per-connection tag (for Tor SOCKS5 stream isloation)
	proxyContext := fmt.Sprintf("session %d", rand.NewMath().Uint64())

	idpubkey, err := cert.Scheme.UnmarshalBinaryPublicKey(s.provider.IdentityKey)
	if err != nil {
		return nil, err
	}

	kemScheme := schemes.ByName(cfg.WireKEMScheme)
	if kemScheme == nil {
		return nil, fmt.Errorf("apparently your KEM Scheme %s doesn't work", cfg.WireKEMScheme)
	}

	clientCfg := &minclient.ClientConfig{
		SphinxGeometry:      cfg.SphinxGeometry,
		User:                string(idHash[:]),
		Provider:            s.provider.Name,
		ProviderKeyPin:      idpubkey,
		LinkKemScheme:       kemScheme,
		LinkKey:             s.linkKey,
		LogBackend:          logBackend,
		PKIClient:           pkiClient,
		CachedDocument:      cachedDoc,
		OnConnFn:            s.onConnection,
		OnMessageFn:         s.onMessage,
		OnACKFn:             s.onACK,
		OnDocumentFn:        s.onDocument,
		DialContextFn:       cfg.UpstreamProxyConfig().ToDialContext(proxyContext),
		PreferedTransports:  cfg.Debug.PreferedTransports,
		MessagePollInterval: time.Duration(cfg.Debug.PollingInterval) * time.Millisecond,
		EnableTimeSync:      false, // Be explicit about it.
	}

	s.timerQ.Start()
	s.Go(s.eventSinkWorker)
	s.Go(s.garbageCollectionWorker)

	s.minclient, err = minclient.New(clientCfg)
	if err != nil {
		return nil, err
	}

	// start the worker
	s.Go(s.worker)

	return s, nil
}

func (s *Session) SphinxGeometry() *geo.Geometry {
	return s.cfg.SphinxGeometry
}

// WaitForDocument blocks until a pki fetch has completed
func (s *Session) WaitForDocument(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return errors.New("Cancelled")
	case <-s.newPKIDoc:
	case <-s.HaltCh():
	}
	return nil
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
	currentEpoch, _, _ := epochtime.Now()

	surbIDMapRange := func(rawSurbID, rawMessage interface{}) bool {
		surbID := rawSurbID.([sConstants.SURBIDLength]byte)
		message := rawMessage.(*Message)
		sentEpoch := uint64(message.SentAt.Sub(epochtime.Epoch)/epochtime.Period)
		if sentEpoch < currentEpoch - 1 {
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

// GetServices returns the services matching the specified service name
func (s *Session) GetServices(serviceName string) ([]*utils.ServiceDescriptor, error) {
	if s.minclient == nil {
		return nil, errors.New("minclient is nil")
	}
	doc := s.minclient.CurrentDocument()
	if doc == nil {
		return nil, errors.New("pki doc is nil")
	}
	descs := utils.FindServices(serviceName, doc)
	if len(descs) == 0 {
		return nil, errors.New("error, GetService failure, service not found in pki doc")
	}
	serviceDescriptors := make([]*utils.ServiceDescriptor, len(descs))
	for i, s := range descs {
		s := s
		serviceDescriptors[i] = &s
	}
	return serviceDescriptors, nil
}

// GetService returns a randomly selected service
// matching the specified service name
func (s *Session) GetService(serviceName string) (*utils.ServiceDescriptor, error) {
	serviceDescriptors, err := s.GetServices(serviceName)
	if err != nil {
		return nil, err
	}
	return serviceDescriptors[rand.NewMath().Intn(len(serviceDescriptors))], nil
}

// OnConnection will be called by the minclient api
// upon connection change status to the Provider
func (s *Session) onConnection(err error) {
	s.log.Debugf("onConnection %v", err)
	s.eventCh.In() <- &ConnectionStatusEvent{
		IsConnected: err == nil,
		Err:         err,
	}
	select {
	case <-s.HaltCh():
	case s.opCh <- opConnStatusChanged{isConnected: err == nil}:
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
	s.log.Infof("OnACK with SURBID %s", idStr)

	rawMessage, ok := s.surbIDMap.Load(*surbID)
	if !ok {
		s.log.Debug("Strange, received reply with unexpected SURBID")
		return nil
	}
	s.surbIDMap.Delete(*surbID)
	msg := rawMessage.(*Message)
	plaintext, err := s.sphinx.DecryptSURBPayload(ciphertext, msg.Key)
	if err != nil {
		s.log.Infof("Discarding SURB Reply, decryption failure: %s", err)
		return nil
	}
	if len(plaintext) != s.geo.ForwardPayloadLength {
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
		// do not block the worker if the receiver timed out!
		select {
		case replyWaitChan <- plaintext:
		default:
			s.log.Warningf("Failed to respond to a blocking message")
			close(replyWaitChan)
		}
	} else {
		s.eventCh.In() <- &MessageReplyEvent{
			MessageID: msg.ID,
			Payload:   plaintext,
			Err:       nil,
		}
	}
	return nil
}

func (s *Session) onDocument(doc *pki.Document) {
	s.log.Debugf("onDocument(): %s", doc)

	if !hmac.Equal(doc.SphinxGeometryHash, s.geo.Hash()) {
		s.log.Errorf("Sphinx Geometry mismatch is set to: \n %s\n", s.geo.Display())
		panic("Sphinx Geometry mismatch!")
	}

	s.hasPKIDoc = true
	select {
	case <-s.HaltCh():
	case s.opCh <- opNewDocument{
		doc: doc,
	}:
	}
	s.eventCh.In() <- &NewDocumentEvent{
		Document: doc,
	}
	select {
	case <-s.HaltCh():
	case s.newPKIDoc <- true:
	default:
	}
}

func (s *Session) CurrentDocument() *pki.Document {
	return s.minclient.CurrentDocument()
}

func (s *Session) Push(i Item) error {
	// Push checks whether a message was ACK'd already and if it has
	// not, reschedules the message for transmission again
	m, ok := i.(*Message)
	if !ok {
		return errors.New("Not Implemented for non-Message types")
	}
	if _, ok := s.surbIDMap.Load(*m.SURBID); ok {
		// still waiting for a SURB-ACK that hasn't arrived
		s.surbIDMap.Delete(*m.SURBID)
		s.opCh <- opRetransmit{msg: m}
	}
	return nil
}

func (s *Session) GetLogger(component string) *logging.Logger {
	return s.logBackend.GetLogger(component)
}

func (s *Session) ForceFetchPKI() {
	s.minclient.ForceFetchPKI()
}

func (s *Session) Shutdown() {
	s.Halt()
	s.timerQ.Halt()
	s.minclient.Shutdown()
	s.minclient.Wait()
}
