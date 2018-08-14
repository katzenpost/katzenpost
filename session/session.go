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

package session

import (
	"encoding/hex"
	"errors"
	"fmt"
	mrand "math/rand"
	"path/filepath"
	"sync"
	"time"

	"github.com/katzenpost/client/config"
	cConstants "github.com/katzenpost/client/constants"
	"github.com/katzenpost/client/internal/pkiclient"
	"github.com/katzenpost/client/poisson"
	"github.com/katzenpost/client/utils"
	cconstants "github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/sphinx"
	"github.com/katzenpost/core/sphinx/constants"
	sConstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/minclient"
	"gopkg.in/op/go-logging.v1"
)

const (
	surbTypeACK       = 0
	surbTypeKaetzchen = 1
	surbTypeInternal  = 2
)

type Session struct {
	worker.Worker

	cfg       *config.Config
	pkiClient pki.Client
	minclient *minclient.Client
	log       *logging.Logger

	fatalErrCh chan error
	haltedCh   chan interface{}
	haltOnce   sync.Once

	// Poisson timers for λP, λD and λL Poisson processes
	// as described in "The Loopix Anonymity System".
	pTimer *poisson.PoissonTimer
	dTimer *poisson.PoissonTimer
	lTimer *poisson.PoissonTimer

	linkKey        *ecdh.PrivateKey
	opCh           chan workerOp
	onlineAt       time.Time
	hasPKIDoc      bool
	condGotPKIDoc  *sync.Cond
	condGotConnect *sync.Cond

	egressQueue    EgressQueue
	surbIDMap      map[[sConstants.SURBIDLength]byte]*MessageRef
	messageIDMap   map[[cConstants.MessageIDLength]byte]*MessageRef
	replyNotifyMap map[[cConstants.MessageIDLength]byte]*sync.Mutex
}

// New establishes a session with provider using key.
// This method will block until session is connected to the Provider.
func New(fatalErrCh chan error, logBackend *log.Backend, cfg *config.Config) (*Session, error) {
	var err error

	// create a pkiclient for our own client lookups
	proxyCfg := cfg.UpstreamProxyConfig()
	pkiClient, err := cfg.NonvotingAuthority.New(logBackend, proxyCfg)
	if err != nil {
		return nil, err
	}

	// create a pkiclient for minclient's use
	pkiClient2, err := cfg.NonvotingAuthority.New(logBackend, proxyCfg)
	if err != nil {
		return nil, err
	}
	pkiCacheClient := pkiclient.New(pkiClient2)

	log := logBackend.GetLogger(fmt.Sprintf("%s@%s_c", cfg.Account.User, cfg.Account.Provider))

	s := &Session{
		cfg:        cfg,
		pkiClient:  pkiClient,
		log:        log,
		fatalErrCh: fatalErrCh,
		opCh:       make(chan workerOp),
	}

	// XXX todo: replace all this with persistent data store
	s.surbIDMap = make(map[[sConstants.SURBIDLength]byte]*MessageRef)
	s.messageIDMap = make(map[[cConstants.MessageIDLength]byte]*MessageRef)
	s.replyNotifyMap = make(map[[cConstants.MessageIDLength]byte]*sync.Mutex)
	s.egressQueue = new(Queue)

	// make some synchronised conditions
	s.condGotPKIDoc = sync.NewCond(new(sync.Mutex))
	s.condGotConnect = sync.NewCond(new(sync.Mutex))

	err = s.loadKeys(cfg.Proxy.DataDir)
	if err != nil {
		return nil, err
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
		DialContextFn:       proxyCfg.ToDialContext("nonvoting:" + cfg.NonvotingAuthority.PublicKey.String()),
		MessagePollInterval: time.Duration(cfg.Debug.PollingInterval) * time.Second,
		EnableTimeSync:      false, // Be explicit about it.
	}

	s.minclient, err = minclient.New(clientCfg)
	if err != nil {
		return nil, err
	}

	s.Go(s.worker)
	return s, nil
}

func (s *Session) loadKeys(basePath string) error {
	// Load link key.
	linkPriv := filepath.Join(basePath, "link.private.pem")
	linkPub := filepath.Join(basePath, "link.public.pem")
	var err error
	if s.linkKey, err = ecdh.Load(linkPriv, linkPub, rand.Reader); err != nil {
		s.log.Errorf("Failure to load link keys: %s", err)
		return err
	}
	return nil
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
		return nil, errors.New("GetService failure, service not found in pki doc.")
	}
	return &serviceDescriptors[mrand.Intn(len(serviceDescriptors))], nil
}

func (s *Session) WaitForPKIDocument() {
	s.condGotPKIDoc.L.Lock()
	defer s.condGotPKIDoc.L.Unlock()
	s.condGotPKIDoc.Wait()
}

// OnConnection will be called by the minclient api
// upon connecting to the Provider
func (s *Session) onConnection(err error) {
	if err == nil {
		s.condGotConnect.L.Lock()
		s.opCh <- opConnStatusChanged{
			isConnected: true,
		}
		s.condGotConnect.Broadcast()
		s.condGotConnect.L.Unlock()
	}
}

// OnMessage will be called by the minclient api
// upon receiving a message
func (s *Session) onMessage(ciphertextBlock []byte) error {
	s.log.Debugf("OnMessage")
	return nil
}

// OnACK is called by the minclient api whe
// we receive an ACK message
func (s *Session) onACK(surbID *[constants.SURBIDLength]byte, ciphertext []byte) error {
	idStr := fmt.Sprintf("[%v]", hex.EncodeToString(surbID[:]))
	s.log.Infof("OnACK with SURBID %x", idStr)

	msgRef, ok := s.surbIDMap[*surbID]
	if !ok {
		s.log.Debug("wtf, received reply with unexpected SURBID")
		return nil
	}
	_, ok = s.replyNotifyMap[*msgRef.ID]
	if !ok {
		s.log.Infof("wtf, received reply with no reply notification mutex, map len is %d", len(s.replyNotifyMap))
		for key, _ := range s.replyNotifyMap {
			s.log.Infof("key %x", key)
		}
		return nil
	}

	plaintext, err := sphinx.DecryptSURBPayload(ciphertext, msgRef.Key)
	if err != nil {
		s.log.Infof("SURB Reply decryption failure: %s", err)
		return err
	}
	if len(plaintext) != cconstants.ForwardPayloadLength {
		s.log.Warningf("Discarding SURB %v: Invalid payload size: %v", idStr, len(plaintext))
		return nil
	}

	switch msgRef.SURBType {
	case surbTypeACK:
		// XXX TODO fix me
	case surbTypeKaetzchen, surbTypeInternal:
		msgRef.Reply = plaintext[2:]
		s.replyNotifyMap[*msgRef.ID].Unlock()
	default:
		s.log.Warningf("Discarding SURB %v: Unknown type: 0x%02x", idStr, msgRef.SURBType)
	}
	return nil
}

func (s *Session) onDocument(doc *pki.Document) {
	s.log.Debugf("onDocument(): Epoch %v", doc.Epoch)
	s.hasPKIDoc = true
	s.condGotPKIDoc.L.Lock()
	s.opCh <- opNewDocument{
		doc: doc,
	}
	s.condGotPKIDoc.Broadcast()
	s.condGotPKIDoc.L.Unlock()
}
