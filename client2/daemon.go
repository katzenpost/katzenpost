package client2

import "github.com/katzenpost/katzenpost/core/worker"

type Daemon struct {
	worker.Worker

	client      *Client
	listener    *listener
	decoySender *decoySender
	egressCh    chan *Request
}

func NewDaemon() (*Daemon, error) {
	return &Daemon{
		egressCh: make(chan *Request),
	}, nil
}

func (d *Daemon) egressWorker() {
	for {
		select {
		case <-d.HaltCh():
			return
		case <-d.egressCh:
			//d.client.SendSphinxPacket()
		}
	}
}

func (d *Daemon) Start() error {

	/*
		rates := &Rates{}
		listener, err := NewListener(rates, egressCh)
		if err != nil {
			return err
		}
	*/
	return nil
}
