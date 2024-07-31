// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"fmt"
	"math"
	"time"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/worker"
)

type opConnStatusChanged struct {
	isConnected bool
}

type opExpNewRate struct {
	averageRate uint64
	maxDelay    uint64
}

type ExpDist struct {
	worker.Worker

	averageRate uint64
	maxDelay    uint64

	opCh  chan interface{}
	outCh chan struct{}
}

func NewExpDist() *ExpDist {
	e := &ExpDist{
		opCh:  make(chan interface{}),
		outCh: make(chan struct{}),
	}
	e.Go(e.worker)
	return e
}

func (e *ExpDist) OutCh() <-chan struct{} {
	return e.outCh
}

func (e *ExpDist) Stop() {
	e.Halt()
}

func (e *ExpDist) UpdateRate(averageRate uint64, maxDelay uint64) {
	e.opCh <- opExpNewRate{
		averageRate: averageRate,
		maxDelay:    maxDelay,
	}
}

func (e *ExpDist) UpdateConnectionStatus(isConnected bool) {
	e.opCh <- opConnStatusChanged{
		isConnected: isConnected,
	}
}

func (e *ExpDist) worker() {
	const maxDuration = math.MaxInt64

	var (
		rateMsec     uint64
		rateTimer    = time.NewTimer(maxDuration)
		rateInterval = time.Duration(maxDuration)
	)

	defer rateTimer.Stop()

	isConnected := false
	mustResetTimer := false

	for {
		var rateFired bool
		var qo interface{}

		select {
		case <-e.HaltCh():
			return
		case <-rateTimer.C:
			rateFired = true
		case qo = <-e.opCh:
		}

		if qo != nil {
			switch op := qo.(type) {
			case opConnStatusChanged:
				isConnected = op.isConnected
				mustResetTimer = true
			case opExpNewRate:
				e.averageRate = op.averageRate
				e.maxDelay = op.maxDelay
				mustResetTimer = true
			default:
				panic(fmt.Sprintf("BUG: Worker received nonsensical op: %T", op))
			} // end of switch
		} else {
			if isConnected {
				if rateFired {
					select {
					case <-e.HaltCh():
						return
					case e.outCh <- struct{}{}:
					}
				}
			}
		}

		if isConnected && e.averageRate != 0 && e.maxDelay != 0 {
			mRng := rand.NewMath()
			rateMsec = uint64(rand.Exp(mRng, float64(1/float64(e.averageRate))))
			if rateMsec > e.maxDelay {
				rateMsec = e.maxDelay
			}
			rateInterval = time.Duration(rateMsec) * time.Millisecond
		} else {
			rateInterval = time.Duration(maxDuration)
		}

		if mustResetTimer {
			rateTimer.Reset(rateInterval)
			mustResetTimer = false
		} else {
			// reset only the timer that fired
			if rateFired {
				rateTimer.Reset(rateInterval)
			}
		}
	} // end for
}
