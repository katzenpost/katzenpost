package client2

import (
	"os"
	"time"

	"github.com/charmbracelet/log"

	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/worker"
)

type sphinxReply struct {
	surbID     *[constants.SURBIDLength]byte
	ciphertext []byte
}

type replyDescriptor struct {
	appID   uint64
	surbKey []byte
}

type Daemon struct {
	worker.Worker

	log        *log.Logger
	cfg        *config.Config
	client     *Client
	listener   *listener
	egressCh   chan *Request
	replies    map[[sConstants.SURBIDLength]byte]replyDescriptor
	timerQueue *TimerQueue
	replyCh    chan sphinxReply
	gcSurbIDCh chan *[sConstants.SURBIDLength]byte
}

func NewDaemon(cfg *config.Config, egressSize int) (*Daemon, error) {
	return &Daemon{
		log: log.NewWithOptions(os.Stderr, log.Options{
			ReportTimestamp: true,
			Prefix:          "client2_daemon",
			Level:           log.DebugLevel,
		}),
		cfg:        cfg,
		egressCh:   make(chan *Request, egressSize),
		replies:    make(map[[sConstants.SURBIDLength]byte]replyDescriptor),
		gcSurbIDCh: make(chan *[sConstants.SURBIDLength]byte),
	}, nil
}

func (d *Daemon) Start() error {
	d.log.Debug("Start")
	var err error
	rates := &Rates{}
	if d.cfg.CachedDocument != nil {
		rates = ratesFromPKIDoc(d.cfg.CachedDocument)
	}

	d.client, err = New(d.cfg)
	if err != nil {
		return err
	}

	d.listener, err = NewListener(d.client, rates, d.egressCh)
	if err != nil {
		return err
	}

	d.cfg.Callbacks = &config.Callbacks{}
	d.cfg.Callbacks.OnACKFn = d.handleReplies
	d.cfg.Callbacks.OnConnFn = d.listener.updateConnectionStatus
	d.cfg.Callbacks.OnDocumentFn = d.listener.updateRatesFromPKIDoc

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

	d.Go(d.egressWorker)
	return d.client.Start()
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
	d.log.Debug("egressWorker")
	for {
		select {
		case <-d.HaltCh():
			return
		case surbID := <-d.gcSurbIDCh:
			delete(d.replies, *surbID)
		case reply := <-d.replyCh:
			desc, ok := d.replies[*reply.surbID]
			if !ok {
				d.log.Infof("reply descriptor not found for SURB ID %x", reply.surbID[:])
			}
			delete(d.replies, *reply.surbID)
			s, err := sphinx.FromGeometry(d.client.cfg.SphinxGeometry)
			if err != nil {
				panic(err)
			}
			plaintext, err := s.DecryptSURBPayload(reply.ciphertext, desc.surbKey)
			if err != nil {
				d.log.Infof("SURB reply decryption error: %s", err.Error())
				continue
			}
			conn, ok := d.listener.conns[desc.appID]
			if !ok {
				d.log.Infof("no connection associated with AppID %d", desc.appID)
			}
			conn.sendResponse(&Response{
				AppID:   desc.appID,
				Payload: plaintext,
			})
		case request := <-d.egressCh:
			surbID := &[sConstants.SURBIDLength]byte{}
			_, err := rand.Reader.Read(surbID[:])
			if err != nil {
				panic(err)
			}

			switch {
			// XXX FIX ME FIXME FIXME
			case request.IsLoopDecoy == true:
			case request.IsDropDecoy == true:
			case request.IsSendOp == true:
				if request.Payload == nil {
					panic("sending payload cannot be nil")
				}
				if len(request.Payload) == 0 {
					panic("sending payload cannot be zero length")
				}

				d.log.Debug("SENDING NOW!")

				surbKey, rtt, err := d.client.SendCiphertext(request.RecipientQueueID, request.DestinationIdHash, surbID, request.Payload)
				if err != nil {
					d.log.Infof("SendCiphertext error: %s", err.Error())
				}

				d.log.Debug("SENT!")

				slop := time.Second * 20
				replyArrivalTime := time.Now().Add(rtt + slop)
				d.log.Infof("reply arrival time: %s", replyArrivalTime)
				d.timerQueue.Push(uint64(replyArrivalTime.UnixNano()), surbID)
				d.replies[*surbID] = replyDescriptor{
					appID:   request.AppID,
					surbKey: surbKey,
				}
			default:
				panic("send operation not fully specified")
			}
		}
	}
}
