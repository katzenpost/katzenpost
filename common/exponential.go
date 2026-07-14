// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"fmt"
	"math"
	"time"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/worker"
)

// safetyCapEps is the tail probability past which the safety cap
// triggers. With epsilon = 10^-12 a sampled delay is clamped roughly
// once per 10^12 draws, vanishing for any honest measurement window.
// The corresponding quantile multiplier is -ln(eps) ≈ 27.63, so the
// cap is about 27.63 × the mean delay.
const safetyCapEps = 1e-12

// SafetyCap returns the (1 - safetyCapEps) quantile of the exponential
// distribution with rate parameter lambda, in milliseconds. It is the
// canonical sampling safety cap for every cover-traffic timing in
// Katzenpost: large enough that clamping is effectively never observed
// (P(clamp) ≈ 10^-12 per draw), so the realised inter-arrival
// distribution is indistinguishable from the unclamped exponential in
// any finite measurement window.
//
// Lambda is in events per millisecond, matching the PKI document's
// LambdaP, LambdaL, LambdaM, LambdaG, LambdaR and Mu fields. Callers
// that previously consumed an operator-supplied *MaxDelay companion
// field should obtain their bound from this function instead; the
// companion fields have been removed from the consensus schema because
// no operator setting produces a useful trade-off.
//
// Returns zero if lambda is non-positive or non-finite; the caller
// should treat zero as "rate-limit disabled" exactly as the
// pre-existing zero-rate paths do.
func SafetyCap(lambda float64) uint64 {
	if lambda <= 0 || math.IsNaN(lambda) || math.IsInf(lambda, 0) {
		return 0
	}
	ms := math.Ceil(-math.Log(safetyCapEps) / lambda)
	if ms > float64(math.MaxUint64) {
		return math.MaxUint64
	}
	return uint64(ms)
}

// LambdaRateToMs converts a PKI lambda parameter (the rate of an Exp
// distribution, in events per millisecond) into the mean delay in
// milliseconds that ExpDist.UpdateRate expects. math.Ceil avoids the
// truncation-to-zero hazard of uint64(1.0 / lambda) when lambda > 1.
func LambdaRateToMs(lambda float64) (uint64, error) {
	if lambda <= 0 || math.IsNaN(lambda) || math.IsInf(lambda, 0) {
		return 0, fmt.Errorf("invalid lambda %v", lambda)
	}
	ms := math.Ceil(1.0 / lambda)
	if ms > float64(math.MaxUint64) {
		return 0, fmt.Errorf("lambda %v produces overflow", lambda)
	}
	return uint64(ms), nil
}

type opConnStatusChanged struct {
	isConnected bool
}

type opExpNewRate struct {
	averageRate uint64
}

// ExpDist provides a pseudorandom ticker writing to OutCh at an
// exponential distribution whose mean inter-arrival is specified via
// UpdateRate. A built-in safety cap drawn from SafetyCap clamps draws
// at the (1 - 10^-12) quantile of the configured distribution; the
// clamp is set far enough into the tail that the realised mean is
// indistinguishable from the unclamped exponential in any honest
// measurement window.
type ExpDist struct {
	worker.Worker

	averageRate uint64
	maxDelay    uint64

	opCh  chan interface{}
	outCh chan struct{}
}

// NewExpDist returns an ExpDist with running worker routine.
func NewExpDist() *ExpDist {
	e := &ExpDist{
		opCh:  make(chan interface{}, 1),
		outCh: make(chan struct{}, 1),
	}
	e.Go(e.worker)
	return e
}

// OutCh returns channel that receives at the rate specified by UpdateRate
func (e *ExpDist) OutCh() <-chan struct{} {
	return e.outCh
}

// UpdateRate takes the mean inter-arrival delay in milliseconds (i.e.
// 1/lambda where lambda is in events per millisecond) and configures
// the worker to emit on OutCh with that mean. Passing zero is treated
// as "disabled" and the worker stops emitting until a positive rate is
// published. The safety cap is derived internally from the mean rate.
func (e *ExpDist) UpdateRate(averageRate uint64) {
	select {
	case <-e.HaltCh():
	case e.opCh <- opExpNewRate{
		averageRate: averageRate,
	}:
	}
}

// UpdateConnectionStatus(true) starts sending to OutCh
// and UpdateConnectionStatus(false) stops sending to OutCh
func (e *ExpDist) UpdateConnectionStatus(isConnected bool) {
	select {
	case <-e.HaltCh():
	case e.opCh <- opConnStatusChanged{isConnected: isConnected}:
	}
}

// applyOp folds one control operation into the worker state and
// returns the updated connection status.
func (e *ExpDist) applyOp(qo interface{}, isConnected bool) bool {
	switch op := qo.(type) {
	case opConnStatusChanged:
		return op.isConnected
	case opExpNewRate:
		e.averageRate = op.averageRate
		// Derive the safety cap from the mean rate so the
		// tail of the exponential is not truncated within
		// any honest measurement window. lambda (events/ms)
		// is the reciprocal of the mean delay; SafetyCap
		// expects lambda. If averageRate is zero the worker
		// is treated as disabled and the cap value is
		// immaterial.
		if e.averageRate != 0 {
			e.maxDelay = SafetyCap(1.0 / float64(e.averageRate))
		} else {
			e.maxDelay = 0
		}
		return isConnected
	default:
		panic(fmt.Sprintf("BUG: Worker received nonsensical op: %T", op))
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

		if qo == nil && rateFired && isConnected {
			// Deliver the tick without starving opCh: the consumer may
			// be gone for good (e.g. a torn-down connection between
			// wire sessions), and UpdateRate/UpdateConnectionStatus
			// must never block behind an undeliverable tick, or the
			// caller deadlocks against this worker. If an op arrives
			// first the tick is dropped; ticks are pure pacing and the
			// op resets the timer anyway.
			select {
			case <-e.HaltCh():
				return
			case e.outCh <- struct{}{}:
			case qo = <-e.opCh:
			}
		}

		if qo != nil {
			isConnected = e.applyOp(qo, isConnected)
			mustResetTimer = true
		}

		// Always recalculate the interval and reset timer when needed
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

		// Reset timer if configuration changed OR if timer fired
		if mustResetTimer || rateFired {
			rateTimer.Reset(rateInterval)
			mustResetTimer = false
		}
	} // end for
}
