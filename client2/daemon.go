// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"fmt"
	"io"
	mrand "math/rand"
	"os"
	"sync"
	"time"

	"github.com/charmbracelet/log"

	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
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

	logbackend io.Writer
	log        *log.Logger
	cfg        *config.Config
	client     *Client
	listener   *listener
	egressCh   chan *Request

	replies map[[sConstants.SURBIDLength]byte]replyDescriptor
	decoys  map[[sConstants.SURBIDLength]byte]replyDescriptor

	timerQueue *TimerQueue
	replyCh    chan sphinxReply
	gcSurbIDCh chan *[sConstants.SURBIDLength]byte
	arq        *ARQ

	gctimerQueue *TimerQueue
	gcReplyCh    chan *gcReply

	haltOnce sync.Once
}

func NewDaemon(cfg *config.Config, egressSize int) (*Daemon, error) {
	var err error
	var logbackend io.Writer

	if cfg.Logging.Disable {
		fmt.Println("WARNING: disabling logging")
		logbackend, err = os.OpenFile("/dev/null", os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
	} else {
		if cfg.Logging.File == "" {
			logbackend = os.Stderr
		} else {
			logbackend, err = os.OpenFile(cfg.Logging.File, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
			if err != nil {
				return nil, err
			}
		}
	}
	logLevel, err := log.ParseLevel(cfg.Logging.Level)
	if err != nil {
		return nil, err
	}
	d := &Daemon{
		logbackend: logbackend,
		log: log.NewWithOptions(logbackend, log.Options{
			ReportTimestamp: true,
			Prefix:          "client2_daemon",
			Level:           logLevel,
		}),
		cfg:        cfg,
		egressCh:   make(chan *Request, egressSize),
		replyCh:    make(chan sphinxReply),
		replies:    make(map[[sConstants.SURBIDLength]byte]replyDescriptor),
		decoys:     make(map[[sConstants.SURBIDLength]byte]replyDescriptor),
		gcSurbIDCh: make(chan *[sConstants.SURBIDLength]byte),
		gcReplyCh:  make(chan *gcReply),
	}

	return d, nil
}

// Shutdown cleanly shuts down a given Server instance.
func (d *Daemon) Shutdown() {
	d.haltOnce.Do(func() { d.halt() })
}

func (d *Daemon) halt() {
	d.log.Debug("Stopping ARQ worker")
	d.arq.Stop()

	d.log.Debug("Stopping thin client listener")
	d.listener.Halt()

	d.log.Debug("Stopping timerQueue")
	d.timerQueue.Halt()
	d.gctimerQueue.Halt()

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

	d.arq = NewARQ(d.client, d, d.log)
	d.arq.Start()

	d.listener, err = NewListener(d.client, rates, d.egressCh, d.logbackend)
	if err != nil {
		return err
	}

	d.cfg.Callbacks = &config.Callbacks{}
	d.cfg.Callbacks.OnACKFn = d.handleReplies
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
	d.gctimerQueue = NewTimerQueue(func(rawGCReply interface{}) {
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
	d.gctimerQueue.Start()

	d.Go(d.egressWorker)
	return d.client.Start()
}

func (d *Daemon) onDocument(doc *cpki.Document) {
	d.listener.updateFromPKIDoc(doc)
}

func (d *Daemon) handleReplies(surbID *[constants.SURBIDLength]byte, ciphertext []byte) error {
	select {
	case d.replyCh <- sphinxReply{
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
			d.Shutdown()
			return
		case mygcreply := <-d.gcReplyCh:
			response := &Response{
				AppID: mygcreply.appID,
				MessageIDGarbageCollected: &MessageIDGarbageCollected{
					MessageID: mygcreply.id,
				},
			}
			conn, ok := d.listener.conns[*mygcreply.appID]
			if !ok {
				d.log.Infof("no connection associated with AppID %x", mygcreply.appID[:])
				panic("no connection associated with AppID")
			}
			err := conn.sendResponse(response)
			if err != nil {
				d.log.Errorf("failed to send Response: %s", err)
			}
		case surbID := <-d.gcSurbIDCh:
			delete(d.replies, *surbID)
			// XXX FIXME consume statistics on our loop decoys for n-1 detection
			delete(d.decoys, *surbID)
		case reply := <-d.replyCh:
			isDecoy := false
			desc, ok := d.replies[*reply.surbID]
			if !ok {
				desc, ok = d.decoys[*reply.surbID]
				if ok {
					isDecoy = true
				} else {
					if d.arq.Has(reply.surbID) {
						myDesc, err := d.arq.HandleAck(reply.surbID)
						if err != nil {
							d.log.Infof("failed to handle ACK")
							continue
						}
						desc = *myDesc
					} else {
						d.log.Infof("reply descriptor not found for SURB ID %x", reply.surbID[:])
						continue
					}
				}

			}
			delete(d.replies, *reply.surbID)
			delete(d.decoys, *reply.surbID)
			s, err := sphinx.FromGeometry(d.client.cfg.SphinxGeometry)
			if err != nil {
				panic(err)
			}
			plaintext, err := s.DecryptSURBPayload(reply.ciphertext, desc.surbKey)
			if err != nil {
				d.log.Infof("SURB reply decryption error: %s", err.Error())
				continue
			}

			// XXX FIXME consume statistics on our loop decoys for n-1 detection
			if isDecoy {
				continue
			}

			conn := d.listener.getConnection(desc.appID)
			if conn == nil {
				d.log.Infof("no connection associated with AppID %x", desc.appID[:])
				panic("no connection associated with AppID")
			}
			conn.sendResponse(&Response{
				AppID: desc.appID,
				MessageReplyEvent: &MessageReplyEvent{
					MessageID: desc.ID,
					SURBID:    reply.surbID,
					Payload:   plaintext,
				},
			})
		case request := <-d.egressCh:
			switch {
			case request.IsLoopDecoy == true:
				d.sendLoopDecoy(request)
			case request.IsDropDecoy == true:
				d.sendDropDecoy()
			case request.IsSendOp == true:
				d.send(request)
			case request.IsARQSendOp == true:
				d.sendARQMessage(request)
			default:
				panic("send operation not fully specified")
			}
		}
	}
}

func (d *Daemon) sendARQMessage(request *Request) {
	if request.AppID == nil {
		panic("request.AppID is nil")
	}
	rtt, err := d.arq.Send(request.AppID, request.ID, request.Payload, request.DestinationIdHash, request.RecipientQueueID)
	if err != nil {
		panic(err)
	}
	slop := time.Second * 20 // XXX perhaps make this configurable if needed
	replyArrivalTime := time.Now().Add(rtt + slop)
	d.gctimerQueue.Push(uint64(replyArrivalTime.UnixNano()), &gcReply{
		id:    request.ID,
		appID: request.AppID,
	})
}

func (d *Daemon) SentEvent(response *Response) {
	if response.AppID == nil {
		panic("response.AppID is nil")
	}
	incomingConn := d.listener.getConnection(response.AppID)
	err := incomingConn.sendResponse(response)
	if err != nil {
		d.log.Errorf("failed to send Response: %s", err)
	}
}

func (d *Daemon) send(request *Request) {
	surbKey := []byte{}
	var rtt time.Duration
	var err error
	var now time.Time

	surbKey, rtt, err = d.client.SendCiphertext(request)
	if err != nil {
		d.log.Infof("SendCiphertext error: %s", err.Error())
	}

	if request.WithSURB {

		now = time.Now()
		slop := time.Second * 20 // XXX perhaps make this configurable if needed
		duration := rtt + slop
		replyArrivalTime := now.Add(duration)

		d.timerQueue.Push(uint64(replyArrivalTime.UnixNano()), request.SURBID)

		if request.IsLoopDecoy == false {
			incomingConn := d.listener.getConnection(request.AppID)
			if incomingConn != nil {
				response := &Response{
					AppID: request.AppID,
					MessageSentEvent: &MessageSentEvent{
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

	if request.IsSendOp {
		d.replies[*request.SURBID] = replyDescriptor{
			appID:   request.AppID,
			surbKey: surbKey,
		}
		return
	}

	if request.IsLoopDecoy {
		d.decoys[*request.SURBID] = replyDescriptor{
			appID:   request.AppID,
			surbKey: surbKey,
		}
		return
	}
}

// ServiceDescriptor describe a mixnet Provider-side service.
type ServiceDescriptor struct {
	// RecipientQueueID is the service name or queue ID.
	RecipientQueueID []byte
	// Provider name.
	MixDescriptor *cpki.MixDescriptor
}

// FindServices is a helper function for finding Provider-side services in the PKI document.
func FindServices(capability string, doc *cpki.Document) []*ServiceDescriptor {
	services := []*ServiceDescriptor{}
	for _, provider := range doc.Providers {
		for cap := range provider.Kaetzchen {
			if cap == capability {
				serviceID := &ServiceDescriptor{
					RecipientQueueID: []byte(provider.Kaetzchen[cap]["endpoint"].(string)),
					MixDescriptor:    provider,
				}
				services = append(services, serviceID)
			}
		}
	}
	return services
}

func (d *Daemon) sendLoopDecoy(request *Request) {
	// XXX FIXME consume statistics on our echo decoys for n-1 detection

	doc := d.client.CurrentDocument()
	if doc == nil {
		panic("doc is nil")
	}
	echoServices := FindServices(EchoService, doc)
	if len(echoServices) == 0 {
		panic("wtf no echo services")
	}
	echoService := echoServices[mrand.Intn(len(echoServices))]

	serviceIdHash := echoService.MixDescriptor.IdentityKey.Sum256()
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
	echoServices := FindServices(EchoService, doc)
	if len(echoServices) == 0 {
		panic("wtf no echo services")
	}
	echoService := echoServices[mrand.Intn(len(echoServices))]

	serviceIdHash := echoService.MixDescriptor.IdentityKey.Sum256()
	payload := make([]byte, d.client.geo.UserForwardPayloadLength)

	request := &Request{}
	request.WithSURB = false
	request.Payload = payload
	request.DestinationIdHash = &serviceIdHash
	request.RecipientQueueID = echoService.RecipientQueueID
	request.IsDropDecoy = true

	d.send(request)
}
