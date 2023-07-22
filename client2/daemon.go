package client2

import (
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/core/worker"
)

type Daemon struct {
	worker.Worker

	cfg      *config.Config
	client   *Client
	listener *listener
	egressCh chan *Request
}

func NewDaemon(cfg *config.Config, egressSize int) (*Daemon, error) {
	return &Daemon{
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

	return nil
}
