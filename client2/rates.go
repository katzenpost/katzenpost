package client2

import cpki "github.com/katzenpost/katzenpost/core/pki"

type Rates struct {
	messageOrLoop         float64
	messageOrLoopMaxDelay uint64

	loop         float64
	loopMaxDelay uint64

	drop         float64
	dropMaxDelay uint64
}

func RatesFromPKIDoc(doc *cpki.Document) *Rates {
	return nil // XXX FIXME
}
