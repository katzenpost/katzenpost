// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

type decoySender struct {
	haltCh                 chan interface{}
	sendMessageOrLoopDecoy *poissonProcess
	sendLoopDecoy          *poissonProcess
	sendDropDecoy          *poissonProcess
}

func newLoopDecoy() *Request {
	return &Request{
		WithSURB:    true,
		IsLoopDecoy: true,
	}
}

func newDropDecoy() *Request {
	return &Request{
		WithSURB:    false,
		IsDropDecoy: true,
	}
}

func newDecoySender(rates *Rates, ingressCh chan *Request, egressCh chan *Request) *decoySender {
	haltCh := make(chan interface{})

	return &decoySender{
		haltCh: haltCh,
		sendMessageOrLoopDecoy: NewPoissonProcess(rates.messageOrLoop, rates.messageOrLoopMaxDelay, func() {
			var m *Request
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

func (d *decoySender) UpdateConnectionStatus(isConnected bool) {
	d.sendMessageOrLoopDecoy.UpdateConnectionStatus(isConnected)
	d.sendLoopDecoy.UpdateConnectionStatus(isConnected)
	d.sendDropDecoy.UpdateConnectionStatus(isConnected)
}

func (d *decoySender) UpdateRates(rates *Rates) {
	d.sendMessageOrLoopDecoy.UpdateRate(rates.messageOrLoop, rates.messageOrLoopMaxDelay)
	d.sendLoopDecoy.UpdateRate(rates.loop, rates.loopMaxDelay)
	d.sendDropDecoy.UpdateRate(rates.drop, rates.dropMaxDelay)
}

func (d *decoySender) Halt() {
	close(d.haltCh)
	d.sendMessageOrLoopDecoy.Halt()
	d.sendLoopDecoy.Halt()
	d.sendDropDecoy.Halt()
}
