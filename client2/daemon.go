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

	log      *log.Logger
	cfg      *config.Config
	client   *Client
	listener *listener
	egressCh chan *Request
	replies  map[[sConstants.SURBIDLength]byte]replyDescriptor
	replyCh  chan sphinxReply
}

func NewDaemon(cfg *config.Config, egressSize int) (*Daemon, error) {
	return &Daemon{
		log: log.NewWithOptions(os.Stderr, log.Options{
			ReportTimestamp: true,
			Prefix:          "client2_daemon",
		}),
		cfg:      cfg,
		egressCh: make(chan *Request, egressSize),
		replies:  make(map[[sConstants.SURBIDLength]byte]replyDescriptor),
	}, nil
}

func (d *Daemon) Start() error {
	rates := &Rates{}
	if d.cfg.CachedDocument != nil {
		rates = ratesFromPKIDoc(d.cfg.CachedDocument)
	}
	var err error
	d.listener, err = NewListener(rates, d.egressCh)
	if err != nil {
		return err
	}
	d.client, err = New(d.cfg)
	if err != nil {
		return err
	}
	d.cfg.OnACKFn = d.handleReplies
	d.Go(d.egressWorker)
	return nil
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
			return
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
			response := &Response{
				AppID:   desc.appID,
				Payload: plaintext,
			}
			conn, ok := d.listener.conns[desc.appID]
			if !ok {
				d.log.Infof("no connection associated with AppID %d", desc.appID)
			}
			conn.sendResponse(response)
		case request := <-d.egressCh:
			surbID := &[sConstants.SURBIDLength]byte{}
			_, err := rand.Reader.Read(surbID[:])
			if err != nil {
				panic(err)
			}
			surbKey, rtt, err := d.client.SendCiphertext(request.RecipientQueueID, request.DestinationIdHash, surbID, request.Payload)
			if err != nil {
				d.log.Infof("SendCiphertext error: %s", err.Error())
			}
			slop := time.Second * 1
			replyArrivalTime := time.Now().Add(rtt + slop)
			d.log.Infof("reply arrival time: %s", replyArrivalTime)
			// XXX FIXME: ADD GC
			d.replies[*surbID] = replyDescriptor{
				appID:   request.AppID,
				surbKey: surbKey,
			}
		}
	}
}
