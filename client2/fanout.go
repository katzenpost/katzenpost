package client2

type fanout struct {
	ingressCh chan *Request
}

func newFanout() *fanout {
	return &fanout{
		ingressCh: make(chan *Request),
	}
}

func (f *fanout) worker() {
	for {
		select {
		case request := <-f.ingressCh:
			if request.IsSendOp {

				// FIXME TODO: fan-out to multiple queues
				// (buffered channels in golang), one for each
				// possible Provider destination in accordance
				// with the current PKI document.

			}

		}
	}
}
