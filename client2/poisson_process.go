package client2

import (
	"fmt"
	"math"
	"time"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/worker"
)

type poissonWorkerOp interface{}

type opConnStatusChanged struct {
	isConnected bool
}

type opNewRate struct {
	lambda         float64
	lambdaMaxDelay uint64
}

type poissonProcess struct {
	worker.Worker

	opCh chan poissonWorkerOp

	lambda         float64
	lambdaMaxDelay uint64

	action func()
}

func NewPoissonProcess(lambda float64, lambdaMaxDelay uint64, action func()) *poissonProcess {
	p := &poissonProcess{
		opCh:           make(chan poissonWorkerOp),
		lambda:         lambda,
		lambdaMaxDelay: lambdaMaxDelay,
		action:         action,
	}
	p.Go(p.worker)
	return p
}

func (p *poissonProcess) UpdateRate(lambda float64, lambdaMaxDelay uint64) {
	p.opCh <- opNewRate{
		lambda:         lambda,
		lambdaMaxDelay: lambdaMaxDelay,
	}
}

func (p *poissonProcess) UpdateConnectionStatus(isConnected bool) {
	p.opCh <- opConnStatusChanged{
		isConnected: isConnected,
	}
}

func (p *poissonProcess) performAction() {
	p.action()
}

func (p *poissonProcess) worker() {
	const maxDuration = math.MaxInt64

	var (
		lambdaMsec     uint64
		lambdaTimer    = time.NewTimer(maxDuration)
		lambdaInterval = time.Duration(maxDuration)
	)

	defer lambdaTimer.Stop()

	isConnected := false
	mustResetTimer := false

	for {
		var lambdaFired bool
		var qo poissonWorkerOp

		select {
		case <-p.HaltCh():
			// Poisson FIFO worker terminating gracefully.
			return
		case <-lambdaTimer.C:
			lambdaFired = true
		case qo = <-p.opCh:
		}

		if qo != nil {
			switch op := qo.(type) {
			case opConnStatusChanged:
				isConnected = op.isConnected
				mustResetTimer = true
			case opNewRate:
				p.lambda = op.lambda
				p.lambdaMaxDelay = op.lambdaMaxDelay
				mustResetTimer = true
			default:
				panic(fmt.Sprintf("BUG: Worker received nonsensical op: %T", op))
			} // end of switch
		} else {
			if isConnected {
				if lambdaFired {
					p.performAction()
				}
			}
		}

		if isConnected && p.lambda != 0 && p.lambdaMaxDelay != 0 {
			mRng := rand.NewMath()
			lambdaMsec = uint64(rand.Exp(mRng, p.lambda))
			if lambdaMsec > p.lambdaMaxDelay {
				lambdaMsec = p.lambdaMaxDelay
			}
			lambdaInterval = time.Duration(lambdaMsec) * time.Millisecond
		} else {
			lambdaInterval = time.Duration(maxDuration)
		}

		if mustResetTimer {
			lambdaTimer.Reset(lambdaInterval)
			mustResetTimer = false
		} else {
			// reset only the timer that fired
			if lambdaFired {
				lambdaTimer.Reset(lambdaInterval)
			}
		}

	} // end for

}
