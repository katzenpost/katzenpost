package client2

import (
	"os"

	"github.com/charmbracelet/log"

	"github.com/katzenpost/katzenpost/client2/config"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/worker"
)

type Daemon struct {
	worker.Worker

	log      *log.Logger
	cfg      *config.Config
	client   *Client
	listener *listener
	egressCh chan *Request
}

func NewDaemon(cfg *config.Config, egressSize int) (*Daemon, error) {
	return &Daemon{
		log: log.NewWithOptions(os.Stderr, log.Options{
			ReportTimestamp: true,
			Prefix:          "client2_daemon",
		}),
		cfg:      cfg,
		egressCh: make(chan *Request, egressSize),
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

	d.Go(d.egressWorker)

	return nil
}

func (d *Daemon) egressWorker() {
	for {
		select {
		case <-d.HaltCh():
			return
		case request := <-d.egressCh:

			surbID := &[sConstants.SURBIDLength]byte{}

			//surbKey, rtt, err := d.client.SendCiphertext(request.RecipientQueueID, request.DestinationIdHash, surbID, request.Payload)
			_, _, err := d.client.SendCiphertext(request.RecipientQueueID, request.DestinationIdHash, surbID, request.Payload)
			if err != nil {
				d.log.Infof("SendCiphertext error: %s", err.Error())
			}
		}
	}
}
