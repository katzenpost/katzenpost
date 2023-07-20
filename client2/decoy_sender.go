package client2

type decoySender struct {
	haltCh                 chan interface{}
	sendMessageOrLoopDecoy *poissonProcess
	sendLoopDecoy          *poissonProcess
	sendDropDecoy          *poissonProcess
}

func newLoopDecoy() *Request {
	return &Request{
		IsLoopDecoy: true,
	}
}

func newDropDecoy() *Request {
	return &Request{
		IsDropDecoy: true,
	}
}

func newDecoySender(rates *Rates, ingressCh chan interface{}, egressCh chan interface{}) *decoySender {
	haltCh := make(chan interface{})

	return &decoySender{
		haltCh: haltCh,
		sendMessageOrLoopDecoy: NewPoissonProcess(rates.messageOrLoop, rates.messageOrLoopMaxDelay, func() {
			var m interface{}
			select {
			case <-haltCh:
				return
			case m = <-ingressCh:
			default:
				m = newLoopDecoy()
			}
			select {
			case <-haltCh:
				return
			case egressCh <- m:
			}
		}),
		sendLoopDecoy: NewPoissonProcess(rates.loop, rates.loopMaxDelay, func() {
			select {
			case <-haltCh:
				return
			case egressCh <- newLoopDecoy():
			}
		}),
		sendDropDecoy: NewPoissonProcess(rates.drop, rates.dropMaxDelay, func() {
			select {
			case <-haltCh:
				return
			case egressCh <- newDropDecoy():
			}
		}),
	}
}

func (d *decoySender) Halt() {
	close(d.haltCh)
	d.sendMessageOrLoopDecoy.Halt()
	d.sendLoopDecoy.Halt()
	d.sendDropDecoy.Halt()
}
