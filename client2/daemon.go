package client2

import (
	mrand "math/rand"
	"os"
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

	replies map[[sConstants.SURBIDLength]byte]replyDescriptor
	decoys  map[[sConstants.SURBIDLength]byte]replyDescriptor

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
		replyCh:    make(chan sphinxReply),
		replies:    make(map[[sConstants.SURBIDLength]byte]replyDescriptor),
		decoys:     make(map[[sConstants.SURBIDLength]byte]replyDescriptor),
		gcSurbIDCh: make(chan *[sConstants.SURBIDLength]byte),
	}, nil
}

func (d *Daemon) Start() error {
	d.log.Debug("Start daemon")
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
	for {
		select {
		case <-d.HaltCh():
			return
		case surbID := <-d.gcSurbIDCh:
			delete(d.replies, *surbID)
			// XXX FIXME consume statistics on our loop decoys for n-1 detection
			delete(d.decoys, *surbID)
		case reply := <-d.replyCh:
			isDecoy := false
			desc, ok := d.replies[*reply.surbID]
			if !ok {
				desc, ok = d.decoys[*reply.surbID]
				if !ok {
					d.log.Infof("reply descriptor not found for SURB ID %x", reply.surbID[:])
					continue
				}
				isDecoy = true
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

			conn, ok := d.listener.conns[desc.appID]
			if !ok {
				d.log.Infof("no connection associated with AppID %d", desc.appID)
				panic("no connection associated with AppID")
			}
			conn.sendResponse(&Response{
				SURBID:  reply.surbID,
				AppID:   desc.appID,
				Payload: plaintext,
			})
		case request := <-d.egressCh:
			switch {
			case request.IsLoopDecoy == true:
				d.sendLoopDecoy(request)
			case request.IsDropDecoy == true:
				d.sendDropDecoy()
			case request.IsSendOp == true:
				d.sendMessage(request)
			default:
				panic("send operation not fully specified")
			}
		}
	}
}

func (d *Daemon) send(request *Request) {
	surbKey, rtt, err := d.client.SendCiphertext(request.RecipientQueueID, request.DestinationIdHash, request.SURBID, request.Payload)
	if err != nil {
		d.log.Infof("SendCiphertext error: %s", err.Error())
	}

	slop := time.Second * 20 // XXX perhaps make this configurable if needed
	duration := rtt + slop
	replyArrivalTime := time.Now().Add(duration)
	d.log.Infof("reply arrival duration: %s", duration)
	d.timerQueue.Push(uint64(replyArrivalTime.UnixNano()), request.SURBID)

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

func (d *Daemon) sendMessage(request *Request) {
	if request.Payload == nil {
		panic("sending payload cannot be nil")
	}
	if len(request.Payload) == 0 {
		panic("sending payload cannot be zero length")
	}

	d.send(request)
}

// ServiceDescriptor describe a mixnet Provider-side service.
type ServiceDescriptor struct {
	// RecipientQueueID is the service name or queue ID.
	RecipientQueueID []byte
	// Provider name.
	MixDescriptor *cpki.MixDescriptor
}

// FindServices is a helper function for finding Provider-side services in the PKI document.
func FindServices(capability string, doc *cpki.Document) []ServiceDescriptor {
	services := []ServiceDescriptor{}
	for _, provider := range doc.Providers {
		for cap := range provider.Kaetzchen {
			if cap == capability {
				serviceID := ServiceDescriptor{
					RecipientQueueID: []byte(provider.Kaetzchen[cap]["endpoint"].(string)),
					MixDescriptor:    provider,
				}
				services = append(services, serviceID)
			}
		}
	}
	return services
}

// XXX FIX ME FIXME FIXME
func (d *Daemon) sendLoopDecoy(request *Request) {
	// XXX FIXME consume statistics on our echo decoys for n-1 detection

	doc := d.client.CurrentDocument()
	echoServices := FindServices(EchoService, doc)
	if len(echoServices) == 0 {
		panic("wtf no echo services")
	}
	echoService := &echoServices[mrand.Intn(len(echoServices))]

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

	d.send(request)
}

// XXX FIX ME FIXME FIXME
func (d *Daemon) sendDropDecoy() {

}
