package client2

type message interface{}

type Rates struct {
	sendRate float64
	loopRate float64
	dropRate float64
}

type decoySender struct {
	haltCh             chan interface{}
	sendMessageOrDecoy *poissonProcess
}

func newDecoySender(rates *Rates, ingressCh chan message, egressCh chan message) *decoySender {
	haltCh := make(chan interface{})

	return &decoySender{
		haltCh: haltCh,
		sendMessageOrDecoy: NewPoissonProcess(rates.sendRate, func() {
			var m message
			select {
			case <-haltCh:
				return
			case m = <-ingressCh:
			default:
				// XXX FIXME
				//m = GenerateDecoy()
			}
			select {
			case <-haltCh:
				return
			case egressCh <- m:
			}
		}),
	}
}

func (d *decoySender) Halt() {
	close(d.haltCh)
	d.sendMessageOrDecoy.Halt()
}
